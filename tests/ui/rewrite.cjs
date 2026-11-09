const fs=require('fs'),assert=require('assert/strict');
const launchBrowser=require('./browser.cjs');
(async()=>{
 const browser=await launchBrowser();
 try{
 const page=await browser.newPage(),errors=[];page.on('pageerror',e=>errors.push(e.message));
 const now=Math.floor(Date.now()/1000);
 const user={name:'phone',enabled:true,password:'example-pass',uuid:'uuid',subToken:'tok',protoOff:[],quotaBytes:0,maxDevices:0,expiresAt:0,up:0,down:0,lastSeen:now,note:'',online:{hysteria2:1},status:'',links:[{proto:'hysteria2',uri:'hysteria2://example'}],subPath:'/sub/tok'};
 const state={users:[user],server:{host:'vpn.example.org',port:'443',protocols:[{id:'hysteria2',title:'Hysteria 2'}]},onlineStatus:{hysteria2:{lastSuccess:now,stale:false}},serverTime:now,onlineFreshFor:30,problems:'',subBase:''};
 let releaseRouter,routerStarted=false,firstState,releaseState,stateRacing=false,stateCalls=0;
 const routerGate=new Promise(r=>releaseRouter=r),stateGate=new Promise(r=>releaseState=r);
 await page.route('https://panel.test/**',async route=>{
  const req=route.request(),url=new URL(req.url());
  if(url.pathname==='/')return route.fulfill({contentType:'text/html',body:fs.readFileSync('index.html','utf8')});
  if(req.method()==='PATCH')return route.fulfill({status:500,body:'disk unavailable'});
  if(url.pathname.endsWith('/mihomo')){
   const body=url.searchParams.get('full');if(body==='router'){routerStarted=true;await routerGate;}
   return route.fulfill({contentType:'text/plain',body});
  }
  let data={status:{},settings:{},agentError:''};
  if(url.pathname==='/api/state'){
   data=structuredClone(state);
   if(stateRacing){stateCalls++;data.server.host=stateCalls===1?'stale.example.org':'fresh.example.org';if(stateCalls===1){firstState=true;await stateGate;}}
  }
  return route.fulfill({contentType:'application/json',body:JSON.stringify(data)});
 });
 await page.goto('https://panel.test/');await page.locator('#app').waitFor({state:'visible'});
 await page.evaluate(()=>openEdit('phone'));await page.locator('#editForm [name="note"]').fill('Заметка не должна потеряться');
 await page.locator('#edit button[value="ok"]').click();await page.getByText('disk unavailable',{exact:true}).waitFor();
 await page.locator('#edit[open]').waitFor();assert.equal(await page.locator('#editForm [name="note"]').inputValue(),'Заметка не должна потеряться');
 await page.evaluate(()=>document.querySelector('#edit').close());
 await page.evaluate(()=>{openShare('phone');mihomoView='router';void setTab('mihomo');});
 for(let i=0;!routerStarted&&i<100;i++)await new Promise(r=>setTimeout(r,10));assert.ok(routerStarted);
 await page.evaluate(()=>{mihomoView='desktop';void setTab('mihomo');});
 await page.waitForFunction(()=>document.querySelector('#shareText').value==='desktop');releaseRouter();
 await page.waitForLoadState('networkidle');assert.equal(await page.locator('#shareText').inputValue(),'desktop');assert.match(await page.evaluate(()=>dlURL),/full=desktop/);
 await page.evaluate(()=>document.querySelector('#share').close());
 stateRacing=true;await page.evaluate(()=>{void load();});
 for(let i=0;!firstState&&i<100;i++)await new Promise(r=>setTimeout(r,10));assert.ok(firstState);
 await page.evaluate(()=>{void load();});await page.getByText('Сервер fresh.example.org',{exact:true}).waitFor();
 releaseState();await page.waitForLoadState('networkidle');assert.equal(await page.locator('#host').innerText(),'Сервер fresh.example.org');
 assert.deepEqual(errors,[]);process.stdout.write('PASS: failed form retains input, reversed Mihomo responses keep selected tab, stale state response cannot overwrite latest\n');
 }finally{await browser.close();}
})().catch(e=>{process.stderr.write(String(e.stack));process.exitCode=1});
