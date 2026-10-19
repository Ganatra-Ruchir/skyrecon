const http=require('node:http'), fs=require('node:fs'), path=require('node:path');
const {chromium}=require('playwright');const assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..');
const server=http.createServer((req,res)=>{let file;try{file=path.resolve(root,'.'+decodeURIComponent(new URL(req.url,'http://localhost').pathname));}catch{res.writeHead(400);return res.end();}if(!file.startsWith(root+path.sep)&&file!==root){res.writeHead(403);return res.end();}if(fs.existsSync(file)&&fs.statSync(file).isDirectory())file=path.join(file,'index.html');if(!fs.existsSync(file)){res.writeHead(404);return res.end();}res.setHeader('Content-Type',({'.html':'text/html; charset=utf-8','.js':'application/javascript; charset=utf-8','.css':'text/css; charset=utf-8'})[path.extname(file)]||'application/octet-stream');fs.createReadStream(file).pipe(res);});
(async()=>{let browser;try{await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));browser=await chromium.launch();const context=await browser.newContext({viewport:{width:1440,height:1080},reducedMotion:'reduce'});const p=await context.newPage();p.setDefaultTimeout(15000);const errors=[];p.on('pageerror',e=>errors.push(e.message));

await p.goto('http://127.0.0.1:'+server.address().port+'/console/index.html',{waitUntil:'domcontentloaded'});

   await p.locator('[data-v="cases"]').click();await p.locator('#newCase').click();await p.locator('#caseTitle').fill('Incident review');await p.locator('#caseOwner').fill('Demo analyst');await p.locator('#casePriority').selectOption('high');await p.locator('#caseNotes').fill('Investigate the supplied sample.');await p.locator('#newTask').fill('Verify source');await p.locator('#addTask').click();await p.locator('[data-task]').check();
   const dl=p.waitForEvent('download');await p.locator('#caseReport').click();assert.equal((await dl).suggestedFilename(),'skyrecon-case-handover.md');
   await p.reload();await p.locator('[data-v="cases"]').click();await p.locator('[data-case]').first().click();assert.equal(await p.locator('#caseOwner').inputValue(),'Demo analyst');assert.equal(await p.locator('[data-task]').isChecked(),true);
   await p.locator('#caseSearch').fill('absent');assert.equal(await p.locator('[data-case]').count(),0);await p.locator('#caseSearch').fill('');

const original=await p.evaluate(()=>localStorage.getItem('skyrecon.cases.v1'));
await p.locator('#importCases').setInputFiles({name:'invalid.json',mimeType:'application/json',buffer:Buffer.from('{"version":1,"cases":[{"title":"bad","notes":"'+ 'x'.repeat(20001)+'"}]}')});
await p.locator('#caseStatus').filter({hasText:'Import failed'}).waitFor();assert.match(await p.locator('#caseStatus').innerText(),/Import failed/);assert.equal(await p.evaluate(()=>localStorage.getItem('skyrecon.cases.v1')),original);
const other=await context.newPage();await other.goto(p.url());await other.locator('[data-v="cases"]').click();await other.locator('[data-case]').first().click();await other.locator('#caseOwner').fill('Other tab');
await p.locator('#caseOwner').fill('Stale write');assert.match(await p.locator('#caseStatus').innerText(),/another tab/);assert.equal(await p.evaluate(()=>JSON.parse(localStorage.getItem('skyrecon.cases.v1')).cases[0].owner),'Other tab');await other.close();
await p.reload();await p.locator('[data-v="cases"]').click();assert.equal(await p.locator('[data-case]').count(),1);

assert.doesNotMatch(await p.locator('body').innerText(),/[\u00c2\u00c3]|\u00e2[\u0080-\u00bf\u20ac\u2020\u20ac]/,'UTF-8 labels must render without mojibake');
assert.deepEqual(errors,[],'Unexpected page errors');await p.setViewportSize({width:390,height:844});await p.waitForTimeout(200);assert.equal(await p.evaluate(()=>document.documentElement.scrollWidth>innerWidth+2),false,'Mobile horizontal overflow');console.log('V2 workflow, exports, reload behavior and mobile checks passed.');
}finally{if(browser)await browser.close();await new Promise(resolve=>server.close(resolve));}})().catch(e=>{console.error(e);process.exitCode=1;});
