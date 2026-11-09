const fs=require('fs'),assert=require('assert/strict');
const launchBrowser=require('./browser.cjs');
(async()=>{
 const browser=await launchBrowser();
 try{
 const page=await browser.newPage({viewport:{width:1024,height:900}}), errors=[];
 page.on('pageerror',e=>errors.push(e.message));
 const now=Math.floor(Date.now()/1000), html=fs.readFileSync('index.html','utf8');
 const user={name:'evo',enabled:true,password:'example-pass',uuid:'example-uuid',subToken:'tok',protoOff:[],quotaBytes:0,maxDevices:0,expiresAt:0,up:10,down:20,lastSeen:now,note:'',resetMonthly:false,online:{hysteria2:1,vless:1},status:'',links:[{proto:'hysteria2',uri:'hysteria2://example'},{proto:'vless',uri:'vless://example'}],subPath:'/sub/tok'};
 const state={users:[user],server:{host:'vpn.example.com',port:'443',protocols:[{id:'hysteria2',title:'Hysteria 2'},{id:'vless',title:'VLESS'}]},onlineStatus:{hysteria2:{lastSuccess:now,stale:false},vless:{lastSuccess:now,stale:false}},serverTime:now,onlineFreshFor:30,problems:'',subBase:'https://vpn.example.com'};
 const system={settings:{hysteria2:{port:'443',obfs:'salamander',domain:'',email:''},vless:{port:'443',sni:'www.example.com',network:'xhttp'}},status:{hysteria2:{installed:true,active:true,version:'2.13.0',latest:'2.13.0'},vless:{installed:true,active:true,version:'25.9.11',latest:'25.9.11'}},agentError:''};
 let job,patch;
 await page.route('https://panel.test/**',async route=>{
  const url=new URL(route.request().url()),method=route.request().method();
  if(url.pathname==='/')return route.fulfill({contentType:'text/html',body:html});
  if(url.pathname.endsWith('/mihomo'))return route.fulfill({contentType:'text/plain',body:'proxies: []\n'});
  let data={};
  if(url.pathname==='/api/state')data=state;
  if(url.pathname==='/api/system')data=system;
  if(url.pathname==='/api/system/check-target')data={ok:true,note:'сайт отвечает'};
  if(url.pathname==='/api/system/releases'){system.status.vless.update=true;system.status.vless.latest='25.10.1';data=system;}
  if(url.pathname==='/api/system/jobs'){job=route.request().postDataJSON();data={running:true};}
  if(url.pathname==='/api/system/job')data={running:false,ok:true,log:'done'};
  if(method==='PATCH'){patch=route.request().postDataJSON();data=user;}
  return route.fulfill({contentType:'application/json',body:JSON.stringify(data)});
 });
 await page.goto('https://panel.test/');await page.locator('#app').waitFor({state:'visible'});
 await page.getByText('VLESS / Reality: работает',{exact:true}).waitFor();
 assert.equal(await page.locator('.server-bar').count(),2);
 assert.equal(await page.locator('#stOnline').innerText(),'1');
 assert.match(await page.locator('#stOnline').getAttribute('title'),/VLESS: 1 IP/);
 assert.equal(await page.locator('#list .sessions').count(),2);
 await page.locator('#serverStatus [data-proto="vless"][data-do="cfg"]').click();
 assert.equal(await page.locator('#vlForm input[name="target"]').inputValue(),'www.example.com');
 await page.locator('#vlForm input[name="port"]').fill('8443');
 await page.locator('#vlInfo [data-do="check"]').click();
 await page.getByText('Версия 25.9.11 · доступна 25.10.1',{exact:true}).waitFor();
 assert.equal(await page.locator('#vlForm input[name="port"]').inputValue(),'8443');
 await page.locator('#vlBtn').click();await page.locator('#jobDlg').waitFor({state:'visible'});
 assert.equal(job.action,'vless');assert.equal(job.params.port,'8443');assert.equal(job.params.target,'www.example.com');
 await page.evaluate(()=>document.querySelector('#jobDlg').close());
 await page.locator('#list [data-a="edit"]').click();
 assert.equal(await page.locator('#protoBoxes input').count(),2);
 await page.locator('#protoBoxes input[data-p="vless"]').uncheck();
 await Promise.all([
  page.waitForResponse(response=>response.request().method()==='PATCH'),
  page.locator('#edit button[value="ok"]').click(),
 ]);
 await page.waitForFunction(()=>!document.querySelector('#edit').open);
 assert.deepEqual(patch.protoOff,['vless']);
 await page.locator('#list [data-a="share"]').click();
 await page.locator('#tabs [data-t="vless"]').click();
 assert.equal(await page.locator('#shareText').inputValue(),'vless://example');
 await page.locator('#tabs [data-t="mihomo"]').click();
 assert.equal(await page.locator('#mtabs button').count(),4);
 await page.setViewportSize({width:375,height:812});
 assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
 await page.evaluate(()=>document.querySelector('#share').close());
 state.onlineStatus.hysteria2.stale=true;state.onlineStatus.hysteria2.lastSuccess=now-60;
 await page.evaluate(()=>load());
 assert.equal(await page.locator('#stOnline').innerText(),'≥ 1');
 assert.equal(await page.locator('.av.on').count(),1);
 assert.match(await page.locator('#list').innerText(),/VLESS: 1 IP/);
 delete system.settings.vless;system.status.vless={};await page.evaluate(()=>loadSystem());
 await page.locator('#serverStatus [data-proto="vless"][data-do="cfg"]').click();
 assert.equal(await page.locator('#vlForm input[name="target"]').inputValue(),'');
 await page.locator('#vlForm input[name="target"]').fill('www.example.org');
 await page.locator('#vlForm button').filter({hasText:'Проверить'}).click();
 await page.waitForFunction(()=>document.querySelector('#vlCheck').textContent.includes('TLS 1.3'));
 assert.deepEqual(errors,[]);
 console.log('PASS: both protocol statuses, unique online users, per-protocol counts, VLESS settings/save, updates, user protocol switches, share tabs, mobile, stale Hy with live VLESS, first VLESS install');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exit(1)});
