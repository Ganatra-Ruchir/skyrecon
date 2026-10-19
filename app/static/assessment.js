'use strict';
(() => {
  let token = '', refresh = '', report = null;
  const $ = id => document.getElementById(id);
  function status(message) { $('status').textContent = message; }
  async function request(path, body, authenticated = true) {
    if (authenticated && !token) throw Error('Sign in to the Python backend first. Static hosting supports the local fixture only.');
    const response = await fetch('/api/' + path, {method:'POST', headers:{'Content-Type':'application/json', ...(token ? {Authorization:'Bearer '+token} : {})}, body:JSON.stringify(body), signal:AbortSignal.timeout(15000)});
    if (!(response.headers.get('content-type') || '').includes('application/json')) throw Error('Python backend unavailable on this host. No assessment was run.');
    if(response.status===204)return {};
    const data = await response.json();
    if (!response.ok) throw Error(typeof data.detail === 'string' ? data.detail : 'Request rejected. Check the field formats and permissions.');
    return data;
  }
  function render(data) {
    report = data; $('results').hidden = false; $('raw').textContent = JSON.stringify(data,null,2);
    $('verdict').textContent = data.verdict || (data.state ? `Catalogue: ${data.state} · ${data.catalogue_count || 0} records loaded` : `${data.owner} · ${data.numbering_region}`);
    $('findings').replaceChildren();
    for (const f of data.findings || []) {
      const card=document.createElement('article'); card.className='finding';
      for(const [tag, text, cls] of [['span',f.severity+' · '+f.status,'badge'],['h3',f.title,''],['p',f.evidence,''],['p','Recommended action: '+f.remediation,'']]) {
        const el=document.createElement(tag); el.textContent=text; el.className=cls; card.append(el);
      }
      $('findings').append(card);
    }
    if (!data.findings) {const p=document.createElement('p');p.textContent=data.attribution || data.limitations; $('findings').append(p);}
  }
  document.querySelectorAll('[data-mode]').forEach(b=>b.addEventListener('click',()=>{
    document.querySelectorAll('[data-mode]').forEach(x=>x.setAttribute('aria-pressed',String(x===b)));
    document.querySelectorAll('.mode').forEach(x=>x.hidden=x.id!==b.dataset.mode);
  }));
  $('motion').onclick=()=>{const paused=document.body.classList.toggle('paused');$('motion').textContent=paused?'Resume motion':'Pause motion';};
  $('login').onsubmit=async e=>{e.preventDefault();try{
    const data=await request('auth/login',{email:$('email').value,password:$('password').value,totp:$('totp').value||null},false);
    token=data.access_token;refresh=data.refresh_token;$('password').value='';$('totp').value='';$('login').hidden=true;$('logout').hidden=false;$('connection').textContent='Connected · '+data.role;status('Authenticated. Live collection requires an approved host.');
  }catch(err){$('password').value='';status(err.message);}};
  $('logout').onclick=async()=>{try{await request('auth/logout',{refresh_token:refresh});}catch{status('Local session cleared. Server revocation could not be confirmed.');}finally{token='';refresh='';report=null;$('results').hidden=true;$('raw').textContent='';$('findings').replaceChildren();$('login').hidden=false;$('logout').hidden=true;$('connection').textContent='Not connected';}};
  for(const mode of ['web','phone','evidence','sarif']) $(mode).onsubmit=async e=>{
    e.preventDefault();const button=e.target.querySelector('button');button.disabled=true;report=null;$('results').hidden=true;status('Review in progress…');
    try {let endpoint=mode,body;
      if(mode==='web'){endpoint='scan';body={url:$('url').value,authorization_reference:$('reference').value};}
      if(mode==='sarif') body={report_json:$('sarif-payload').value};
      if(mode==='phone') body={number:$('number').value};
      if(mode==='evidence'){if($('payload').value.length>262144)throw Error('Evidence exceeds 256 KB.');body=JSON.parse($('payload').value);}
      render(await request('assessment/'+endpoint,body));status('Review complete. Read the limitations before acting.');
    }catch(err){status(err.message);}finally{button.disabled=false;}
  };
  $('catalogue').onsubmit=async e=>{e.preventDefault();try{if(!token)throw Error('Sign in to the Python backend first.');const r=await fetch('/api/assessment/catalogue?q='+encodeURIComponent($('query').value),{headers:{Authorization:'Bearer '+token}});if(!r.ok)throw Error('Catalogue request unavailable');render(await r.json());status('Reference results only; no target vulnerabilities confirmed.');}catch(err){status(err.message);}};
  $('demo').onclick=async()=>{try{const r=await fetch('assessment-fixture.json');if(!r.ok)throw Error('Fixture unavailable');render(await r.json());status('LOCAL FIXTURE — example.com was not contacted. This is not a live scan.');$('results').scrollIntoView({block:'start'});}catch(err){status(err.message);}};
  $('export').onclick=()=>{if(!report)return;const url=URL.createObjectURL(new Blob([JSON.stringify(report,null,2)],{type:'application/json'}));const a=document.createElement('a');a.href=url;a.download='skyrecon-assessment.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);};
  $('print').onclick=()=>{$('results').querySelector('details').open=true;window.print();};
})();
