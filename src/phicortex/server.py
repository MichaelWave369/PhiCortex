"""Loopback-only HTTP API. Conversation storage is disabled until explicitly opted in."""
from __future__ import annotations

import json
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs

from .core import Config, Cortex, RequestError
from .history import HistoryError
from .colony import overview, registry

MAX_REQUEST = 1_048_576
MAX_HISTORY_REQUEST = 64 * 1024
WEB_DIR = Path(__file__).with_name('web')


def make_handler(cortex: Cortex):
    class Handler(BaseHTTPRequestHandler):
        def respond(self, status: int, data: dict | list | None) -> None:
            body = b'' if status == 204 else json.dumps(data).encode('utf-8')
            self.send_response(status)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Security-Policy', "default-src 'none'; connect-src 'self'; script-src 'self'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'")
            self.end_headers()
            if body:
                self.wfile.write(body)

        def _boundary(self) -> bool:
            port = self.server.server_address[1]
            host = self.headers.get('Host','')
            if host not in (f'127.0.0.1:{port}',f'localhost:{port}'):
                self.respond(403, {'error':{'message':'loopback host required'}})
                return False
            origin = self.headers.get('Origin')
            if origin is not None and origin != 'http://' + host:
                self.respond(403, {'error':{'message':'cross-origin request rejected'}})
                return False
            return True

        def _json_body(self, limit: int = MAX_REQUEST) -> dict:
            try:
                length = int(self.headers.get('Content-Length','0'))
            except ValueError as exc:
                raise RequestError('invalid content length',400) from exc
            if length < 1 or length > limit:
                raise RequestError('invalid or oversized JSON request',413 if length>limit else 400)
            try:
                body = json.loads(self.rfile.read(length))
            except (ValueError, UnicodeDecodeError) as exc:
                raise RequestError('invalid JSON request',400) from exc
            if not isinstance(body,dict):
                raise RequestError('JSON body must be an object',400)
            return body

        def _parts(self):
            url = urlsplit(self.path)
            return url.path, parse_qs(url.query,keep_blank_values=True)

        @staticmethod
        def _int(params:dict, name:str, default:int, lo:int, hi:int) -> int:
            try:
                value = int(params[name][0]) if name in params else default
            except (TypeError,ValueError,IndexError) as exc:
                raise RequestError(f'{name} must be an integer',400) from exc
            if not lo <= value <= hi:
                raise RequestError(f'{name} out of range',400)
            return value

        @staticmethod
        def _optional_id(params:dict, name:str) -> int | None:
            if name not in params:
                return None
            return Handler._int(params,name,1,1,2**63-1)

        def _write_guard(self) -> None:
            if self.headers.get('X-PhiCortex-Request') != '1' and self.headers.get('X-Mesh-Request') != '1':
                raise RequestError('conversation writes require X-PhiCortex-Request: 1',403)

        def _api(self, verb:str) -> None:
            path, params = self._parts()
            if verb == 'GET' and path in ('/', '/assets/app.js', '/assets/style.css'):
                mapping={'/':('index.html','text/html; charset=utf-8'),
                         '/assets/app.js':('app.js','text/javascript; charset=utf-8'),
                         '/assets/style.css':('style.css','text/css; charset=utf-8')}
                filename,content_type=mapping[path]
                data=(WEB_DIR / filename).read_bytes()
                self.send_response(200)
                self.send_header('Content-Type',content_type)
                self.send_header('Content-Length',str(len(data)))
                self.send_header('X-Content-Type-Options','nosniff')
                self.send_header('Cache-Control','no-store')
                self.send_header('Content-Security-Policy',"default-src 'none'; connect-src 'self'; script-src 'self'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'")
                self.end_headers()
                self.wfile.write(data)
                return
            if path == '/health' and verb == 'GET':
                self.respond(200,{'status':'ok','phase':1,'events':cortex.ledger.count(),
                                  'cpu_first':'not_verified','history_enabled':cortex.history is not None})
                return
            if path == '/v1/models' and verb == 'GET':
                models = sorted(set(registry(cortex.config).values()))
                self.respond(200, {'object': 'list', 'data': [
                    {'id': 'phicortex-auto', 'object': 'model'}] +
                    [{'id': model, 'object': 'model'} for model in models]})
                return
            if path == '/v1/colony' and verb == 'GET':
                self.respond(200, overview(cortex.config))
                return
            if path == '/v1/telemetry' and verb == 'GET':
                self.respond(200, cortex.ledger.metrics())
                return
            if path == '/v1/chat/completions' and verb == 'POST':
                self.respond(200,cortex.chat(self._json_body()))
                return

            if not path.startswith('/api/v1/'):
                raise RequestError('not found',404)
            history=cortex._history()
            seg=path[len('/api/v1/'):].split('/')
            if seg == ['status'] and verb == 'GET':
                self.respond(200,{'storage':'enabled','inference':'not_probed',
                                  'models':sorted(set(registry(cortex.config).values()))})
                return
            if seg == ['conversations']:
                if verb == 'GET':
                    self.respond(200,history.list(self._int(params,'offset',0,0,1000000),
                                                 self._int(params,'limit',40,1,100)))
                    return
                if verb == 'POST':
                    self._write_guard()
                    self.respond(201,history.create())
                    return
            if seg == ['search'] and verb == 'GET':
                query=params.get('q',[''])[0]
                if not 1 <= len(query) <= 160:
                    raise RequestError('search query must be 1-160 characters')
                self.respond(200,history.search(query,self._int(params,'limit',40,1,100)))
                return
            if len(seg) >= 2 and seg[0] == 'conversations':
                conv_id=cortex._uuid(seg[1])
                if len(seg) == 2:
                    if verb == 'GET':
                        self.respond(200,history.page(conv_id,self._int(params,'limit',40,1,100),
                            self._optional_id(params,'before'),self._optional_id(params,'through')))
                        return
                    if verb == 'DELETE':
                        self._write_guard()
                        cortex.delete_conversation(conv_id)
                        self.respond(204,None)
                        return
                if len(seg) == 3 and seg[2] == 'turns' and verb == 'POST':
                    self._write_guard()
                    self.respond(200,cortex.complete_turn(conv_id,self._json_body(MAX_HISTORY_REQUEST)))
                    return
            raise RequestError('not found',404)

        def do_GET(self):
            self._dispatch('GET')

        def do_POST(self):
            self._dispatch('POST')

        def do_DELETE(self):
            self._dispatch('DELETE')

        def _dispatch(self, verb):
            if not self._boundary():
                return
            try:
                self._api(verb)
            except RequestError as exc:
                self.respond(exc.status, {'error':{'message':str(exc)}})
            except HistoryError as exc:
                self.respond(exc.status, {'error':{'message':str(exc)}})

    return Handler


def run() -> None:
    config=Config.from_env()
    cortex=Cortex(config)
    server=ThreadingHTTPServer(('127.0.0.1',8765),make_handler(cortex))
    try:
        print('PhiCortex listening at http://127.0.0.1:8765 (history opt-in)',flush=True)
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        cortex.close()
