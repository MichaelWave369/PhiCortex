/* PhiCortex original local UI; all model and saved text is rendered as text, never HTML. */
(() => {
  'use strict';
  const $ = (id) => document.getElementById(id);
  const elements = {
    status:$('status'), chats:$('conversations'), search:$('search'), hits:$('search-results'),
    messages:$('messages'), form:$('composer'), prompt:$('prompt'), send:$('send'),
    notice:$('notice'), newChat:$('new-chat'),
  };
  let active = null;
  let busy = false;
  const writeHeaders = {'Content-Type':'application/json', 'X-PhiCortex-Request':'1'};
  async function api(path, opts={}) {
    const response = await fetch('/api/v1'+path, {cache:'no-store', ...opts});
    if (!response.ok) {
      let message='Request failed: '+response.status;
      try { const data=await response.json(); message=data.error?.message || message; } catch {}
      throw new Error(message);
    }
    return response.status===204?null:response.json();
  }
  function notice(text) { elements.notice.textContent=text; }
  function clear(node){ node.replaceChildren(); }
  function entry(buttonText, click, target, secondary='') {
    const button=document.createElement('button');
    button.type='button'; button.textContent=buttonText;
    if (secondary) { const small=document.createElement('small'); small.textContent=secondary; button.append(small); }
    button.addEventListener('click',click);
    target.append(button);return button;
  }
  function bubble(role,content) {
    const node=document.createElement('div');
    node.className='bubble '+role;
    node.textContent=content;
    elements.messages.append(node);
    elements.messages.scrollTop=elements.messages.scrollHeight;
  }
  async function loadConversations(){
    const data=await api('/conversations?limit=40'); clear(elements.chats);
    for(const item of data){
      const btn=entry(item.title,()=>openConversation(item.id),elements.chats);
      if(item.id===active)btn.classList.add('selected');
    }
  }
  async function openConversation(id) {
    active=id;
    const page=await api('/conversations/'+encodeURIComponent(id));
    clear(elements.messages);
    if (!page.turns.length) bubble('assistant','Start a conversation. This workspace keeps the complete chat on your local disk.');
    for(const turn of page.turns){bubble('user',turn.user_text);bubble('assistant',turn.assistant_text);}
    await loadConversations();
    notice(page.older_before?'Showing recent messages only. Older turns remain searchable.':'Ready.');
  }
  async function createConversation(){
    if(busy)return;
    const result=await api('/conversations',{method:'POST',headers:writeHeaders,body:'{}'});
    await openConversation(result.id);
    elements.prompt.focus();
  }
  async function search(){
    const q=elements.search.value.trim(); clear(elements.hits);
    if(!q)return;
    try {
      const results=await api('/search?q='+encodeURIComponent(q)+'&limit=20');
      if(!results.length) {entry('No matching saved turns',()=>{},elements.hits);return;}
      for(const hit of results){entry(hit.title,()=>openConversation(hit.conversation_id),elements.hits,hit.excerpt||'');}
    } catch(err){notice(err.message);}
  }
  async function submit(evt){
    evt.preventDefault();
    const message=elements.prompt.value.trim();
    if(!message||busy)return;
    busy=true;elements.send.disabled=true;
    try{
      if(!active){const conv=await api('/conversations',{method:'POST',headers:writeHeaders,body:'{}'});active=conv.id;}
      bubble('user',message);
      elements.prompt.value='';notice('Generating locally…');
      const result=await api('/conversations/'+encodeURIComponent(active)+'/turns',{
        method:'POST',headers:writeHeaders,body:JSON.stringify({request_id:crypto.randomUUID(),message})
      });
      bubble('assistant',result.assistant_text);
      notice('Saved locally · '+result.elapsed_ms+' ms');
      await loadConversations();
    } catch(err) {notice(err.message);elements.prompt.value=message;}
    finally {busy=false;elements.send.disabled=false;}
  }
  elements.form.addEventListener('submit',submit);
  elements.newChat.addEventListener('click',()=>createConversation().catch(err=>notice(err.message)));
  elements.search.addEventListener('input',()=>search());
  async function init(){
    try {
      const health=await fetch('/health',{cache:'no-store'}).then(r=>r.json());
      if(!health.history_enabled){
        elements.status.textContent='History disabled';
        notice('Restart with PHICORTEX_ENABLE_HISTORY=1 to enable local conversations.');
        elements.send.disabled=true;elements.newChat.disabled=true;return;
      }
      elements.status.textContent='Local workspace';
      await loadConversations();
      notice('Connected to local gateway. Actual model readiness is checked on send.');
    } catch(err){elements.status.textContent='Unavailable';notice(err.message);}
  }
  init();
})();
