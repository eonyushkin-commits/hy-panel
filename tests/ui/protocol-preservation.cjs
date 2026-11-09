const fs=require('fs'),assert=require('assert/strict');
const launchBrowser=require('./browser.cjs');
(async()=>{
 const browser=await launchBrowser();
 try{
 const page=await browser.newPage();const now=Math.floor(Date.now()/1000);let sent;
 const user={name:'alice',enabled:true,password:'example-pass',protoOff:['vless'],quotaBytes:0,maxDevices:0,expiresAt:0,up:0,down:0,lastSeen:0,note:'',resetMonthly:false,online:{},status:'',links:[{proto:'hysteria2',uri:'hysteria2://example'}]};
 const state={users:[user],server:{host:'vpn.example.com',port:'443',protocols:[{id:'hysteria2',title:'Hysteria 2'}]},onlineStatus:{hysteria2:{lastSuccess:now,stale:false}},serverTime:now,onlineFreshFor:30,problems:'',subBase:''};
 await page.route('https://panel.test/**',async route=>{
  const path=new URL(route.request().url()).pathname;
  if(path==='/')return route.fulfill({contentType:'text/html',body:fs.readFileSync('index.html','utf8')});
  let data=path==='/api/state'?state:path==='/api/system'?{settings:{hysteria2:{port:'443'}},status:{},agentError:''}:user;
  if(route.request().method()==='PATCH')sent=route.request().postDataJSON();
  return route.fulfill({contentType:'application/json',body:JSON.stringify(data)});
 });
 await page.goto('https://panel.test/');await page.locator('#app').waitFor({state:'visible'});
 await page.locator('#list [data-a="edit"]').click();
 assert.equal(await page.locator('#protoWrap').isVisible(),false);
 await page.locator('#editForm input[name="note"]').fill('Changed note only');
 await page.locator('#edit button[value="ok"]').click();
 await page.waitForTimeout(100);
 console.log(JSON.stringify({before:user.protoOff,after:sent.protoOff,note:sent.note}));
 assert.deepEqual(sent.protoOff,['vless']);
 state.server.protocols.push({id:'vless',title:'VLESS'});
 await page.evaluate(()=>load());
 await page.locator('#list [data-a="edit"]').click();
 await page.locator('#protoBoxes input[data-p="vless"]').check();
 await page.locator('#edit button[value="ok"]').click();
 await page.waitForTimeout(100);
 assert.deepEqual(sent.protoOff,[]);
 state.server.protocols=[];
 user.protoOff=['hysteria2','vless'];
 await page.evaluate(()=>load());
 await page.locator('#list [data-a="edit"]').click();
 await page.locator('#edit button[value="ok"]').click();
 await page.waitForTimeout(100);
 assert.deepEqual(sent.protoOff,['hysteria2','vless']);
 console.log('PASS: absent protocol restrictions preserved, visible switches editable, all restrictions preserved without configured protocols');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exit(1)});
