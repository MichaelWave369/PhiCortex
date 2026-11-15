"""Conversation API and persistence acceptance tests with a deterministic fake model."""
import http.client
import json
import os
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from uuid import uuid4

from phicortex.core import Config, Cortex, RequestError
from phicortex.history import HistoryStore
from phicortex.server import make_handler


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.database=os.path.join(self.tmp.name,'phicortex.sqlite3')
        self.calls=[]
        def transport(cfg,payload):
            self.calls.append(payload)
            return {'id':'mock','object':'chat.completion','model':payload['model'],
                    'choices':[{'message':{'role':'assistant','content':'Juniper trilobite.'},'finish_reason':'stop'}],
                    'usage':{'prompt_tokens':18,'completion_tokens':3}}
        self.cortex=Cortex(Config(db_path=self.database,enable_history=True,chat_model='chat',code_model='code'),transport)
        self.server=ThreadingHTTPServer(('127.0.0.1',0),make_handler(self.cortex))
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.cortex.close()

    def request(self,method,path,body=None,headers=None):
        conn=http.client.HTTPConnection('127.0.0.1',self.server.server_port,timeout=3)
        conn.request(method,path,json.dumps(body) if body is not None else None,headers or {})
        resp=conn.getresponse()
        raw=resp.read()
        out=json.loads(raw) if raw else None
        status=resp.status
        conn.close()
        return status,out

    def create(self):
        status,conv=self.request('POST','/api/v1/conversations',{}, {'X-Mesh-Request':'1'})
        self.assertEqual(status,201)
        return conv['id']

    def send(self,conv,message,reqid=None):
        return self.request('POST',f'/api/v1/conversations/{conv}/turns',
                            {'request_id':reqid or str(uuid4()),'message':message},
                            {'X-PhiCortex-Request':'1'})

    def test_history_requires_opt_in(self):
        other=Cortex(Config(db_path=os.path.join(self.tmp.name,'nohistory.db')))
        try:
            with self.assertRaises(RequestError) as err:
                other._history()
            self.assertEqual(err.exception.status,501)
        finally:
            other.close()

    def test_create_store_search_and_restart(self):
        conv=self.create()
        status,turn=self.send(conv,'Project codename is Juniper.')
        self.assertEqual(status,200)
        self.assertEqual(turn['assistant_text'],'Juniper trilobite.')
        self.assertEqual(turn['prompt_tokens'],18)
        self.assertFalse(turn['context_trimmed'])
        status,results=self.request('GET','/api/v1/search?q=Juniper')
        self.assertEqual(status,200)
        self.assertEqual(len(results),1)
        self.assertEqual(results[0]['conversation_id'],conv)
        status,page=self.request('GET',f'/api/v1/conversations/{conv}')
        self.assertEqual(len(page['turns']),1)
        self.assertEqual(page['conversation']['title'],'Project codename is Juniper.')
        # Independent store connection confirms data survives a process-level reopen.
        other=HistoryStore(self.database)
        try:
            self.assertEqual(len(other.page(conv)['turns']),1)
            self.assertEqual(other.search('trilobite')[0]['conversation_id'],conv)
        finally:
            other.close()

    def test_replay_does_not_call_model_twice(self):
        conv=self.create()
        request_id=str(uuid4())
        a=self.send(conv,'Hi there',request_id)
        b=self.send(conv,'Hi there',request_id)
        c=self.send(conv,'Changed message',request_id)
        self.assertEqual(a[0],200)
        self.assertEqual(a,b)
        self.assertEqual(c[0],409)
        self.assertEqual(len(self.calls),1)

    def test_failures_never_commit_half_turn(self):
        conv=self.create()
        self.cortex.transport=lambda cfg,payload: {'choices':[]}
        status,_=self.send(conv,'Please fail')
        self.assertEqual(status,502)
        _,page=self.request('GET',f'/api/v1/conversations/{conv}')
        self.assertEqual(page['turns'],[])
        _,hits=self.request('GET','/api/v1/search?q=fail')
        self.assertEqual(hits,[])

    def test_delete_removes_search_hits(self):
        conv=self.create()
        self.send(conv,'A purple tomato')
        self.assertEqual(self.request('DELETE',f'/api/v1/conversations/{conv}',headers={'X-Mesh-Request':'1'})[0],204)
        self.assertEqual(self.request('GET','/api/v1/search?q=tomato'),(200,[]))
        self.assertEqual(self.request('GET',f'/api/v1/conversations/{conv}')[0],404)

    def test_request_guards_and_host(self):
        self.assertEqual(self.request('POST','/api/v1/conversations',{})[0],403)
        self.assertEqual(self.request('GET','/api/v1/conversations',headers={'Host':'evil.test'})[0],403)
        self.assertEqual(self.request('GET','/api/v1/conversations',headers={'Origin':'https://evil.test'})[0],403)
        self.assertEqual(self.request('POST','/api/v1/conversations',{}, {'X-Mesh-Request':'1'},)[0],201)

    def test_context_carries_prior_turn(self):
        conv=self.create()
        self.send(conv,'My secret codename is Juniper.')
        self.send(conv,'What is my codename?')
        self.assertEqual(len(self.calls),2)
        self.assertTrue(any('secret codename' in m['content'] for m in self.calls[1]['messages']))

    def test_cursor_history(self):
        conv=self.create()
        a=self.send(conv,'One')[1]['id']
        b=self.send(conv,'Two')[1]['id']
        _,recent=self.request('GET',f'/api/v1/conversations/{conv}?limit=1')
        self.assertEqual(recent['turns'][0]['id'],b)
        self.assertEqual(recent['older_before'],b)
        _,past=self.request('GET',f'/api/v1/conversations/{conv}?before={b}')
        self.assertEqual([t['id'] for t in past['turns']],[a])
        self.assertEqual(self.request('GET',f'/api/v1/conversations/{conv}?before={b}&through={a}')[0],400)

    def test_search_metacharacters_safe(self):
        conv=self.create()
        self.send(conv,'trilobite')
        self.assertEqual(self.request('GET','/api/v1/search?q=%22%20*')[0],200)
        self.assertEqual(self.request('GET','/api/v1/search?q=%22%20*')[1],[])

    def test_busy_generation_returns_conflict(self):
        conv=self.create()
        started=threading.Event()
        release=threading.Event()
        def slow(cfg,p):
            started.set()
            self.assertTrue(release.wait(2))
            return {'model':p['model'],'choices':[{'message':{'content':'complete'},'finish_reason':'stop'}]}
        self.cortex.transport=slow
        result=[]
        runner=threading.Thread(target=lambda: result.append(self.send(conv,'First')))
        runner.start()
        try:
            self.assertTrue(started.wait(2))
            self.assertEqual(self.send(conv,'Second')[0],409)
            self.assertEqual(self.request('DELETE',f'/api/v1/conversations/{conv}',headers={'X-Mesh-Request':'1'})[0],409)
        finally:
            release.set()
            runner.join(3)
        self.assertEqual(result[0][0],200)

if __name__ == '__main__':
    unittest.main()

class BrowserAssetTests(unittest.TestCase):
    def test_ui_assets_available_without_executing_remote_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            cortex=Cortex(Config(db_path=os.path.join(tmp,'db.sqlite3')))
            server=ThreadingHTTPServer(('127.0.0.1',0),make_handler(cortex))
            thread=threading.Thread(target=server.serve_forever,daemon=True)
            thread.start()
            try:
                for path,mime in (('/','text/html'),('/assets/app.js','text/javascript'),('/assets/style.css','text/css')):
                    conn=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=3)
                    conn.request('GET',path)
                    response=conn.getresponse()
                    data=response.read()
                    self.assertEqual(response.status,200)
                    self.assertIn(mime,response.getheader('Content-Type'))
                    self.assertTrue(data)
                    conn.close()
            finally:
                server.shutdown();server.server_close();thread.join();cortex.close()
