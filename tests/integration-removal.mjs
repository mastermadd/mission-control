import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import vm from 'node:vm';
import {passwordHash} from '../auth.mjs';
import {startServer} from '../server.mjs';
import {encrypt,decrypt} from '../lib/security.js';

test('Integration deletion accepts empty/JSON bodies, deletes all connector caches and keeps malformed JSON rejected',async()=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'mission-delete-'));
  const config={origin:'http://localhost:8080',username:'admin',password:passwordHash('fixture-admin-password'),encryptionKey:'be'.repeat(32)};
  const app=startServer(config,{database:path.join(dir,'db.sqlite'),port:0,host:'127.0.0.1',poll:false});
  await new Promise(resolve=>app.server.once('listening',resolve));
  const base='http://127.0.0.1:'+app.server.address().port;let cookie='';
  async function request(url,method='GET',raw,headers={}){const response=await fetch(base+url,{method,headers:{Origin:config.origin,'Content-Type':'application/json',Cookie:cookie,...headers},...(raw===undefined?{}:{body:raw})});return {status:response.status,cookie:response.headers.get('set-cookie'),data:await response.json()};}
  const secret={username:'fixture-reader',password:'FIXTURE-SECRET'};
  try {
    const login=await request('/auth/login','POST',JSON.stringify({username:'admin',password:'fixture-admin-password'}));cookie=login.cookie.split(';')[0];
    const encrypted=await encrypt(secret,config.encryptionKey,'local-admin:legacy');
    async function insert(id,connector){await app.db.prepare('INSERT INTO integrations (id,owner,connector,name,endpoint,mode,auth,encrypted,status,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)').bind(id,'local-admin',connector,'Router','https://router.internal','direct','basic',encrypted,'Connected','now').run();await app.db.prepare('INSERT INTO classic_cache (id,owner,revision,snapshot,last_success) VALUES (?,?,?,?,?)').bind(id,'local-admin',0,JSON.stringify({sites:[]}),'now').run();}
    for(const [index,connector] of ['generic','unifi-classic','pangolin','mikrotik-api','mikrotik'].entries()){
      const id='delete-'+index;await insert(id,connector);
      assert.equal((await request('/api/integrations/'+id,'DELETE','{')).status,400);
      assert(await app.db.prepare('SELECT id FROM integrations WHERE id=?').bind(id).first());
      assert.equal((await request('/api/integrations/'+id,'DELETE',undefined,{Origin:'http://evil.test'})).status,403);
      const removed=await request('/api/integrations/'+id,'DELETE',index%2?'{}':undefined);
      assert.equal(removed.status,200,JSON.stringify(removed.data));assert.equal(removed.data.deleted,true);
      assert.equal(await app.db.prepare('SELECT * FROM integrations WHERE id=?').bind(id).first(),null);
      assert.equal(await app.db.prepare('SELECT * FROM classic_cache WHERE id=?').bind(id).first(),null);
    }
    await insert('generic-legacy','generic');
    const before=await app.db.prepare('SELECT * FROM integrations WHERE id=?').bind('generic-legacy').first();
    let probes=0;const originalFetch=globalThis.fetch;
    globalThis.fetch=async(url,options)=>{if(String(url).startsWith('https://router.internal')){probes++;throw Error('Retired connector must never probe');}return originalFetch(url,options);};
    try{
      for(const action of ['test','poll']){
        const disabled=await request('/api/integrations/generic-legacy/'+action,'POST','{}');
        assert.equal(disabled.data.status,'Connector removed');assert.match(disabled.data.error,/dedicated connector/);
      }
      await app.pollAll();assert.equal(probes,0);
      assert.deepEqual(await app.db.prepare('SELECT * FROM integrations WHERE id=?').bind('generic-legacy').first(),before);
      const list=await request('/api/integrations');assert.equal(list.data.integrations[0].status,'Connector removed');
      assert(!JSON.stringify(list.data).includes(secret.password));
      for(const connector of ['generic',undefined])assert.equal((await request('/api/integrations','POST',JSON.stringify({name:'Unsupported',connector,mode:'direct',auth:'basic',endpoint:'https://router.internal',credential:secret}))).status,400);
      assert.equal((await request('/api/integrations/generic-legacy','PATCH',JSON.stringify({name:'Unsupported',connector:'generic',mode:'direct',auth:'basic',endpoint:'https://router.internal'}))).status,400);
    }finally{globalThis.fetch=originalFetch;}
    assert.equal((await request('/api/integrations/generic-legacy','DELETE')).status,200);
    await insert('legacy','mikrotik');
    const list=await request('/api/integrations');assert.equal(list.data.integrations[0].status,'Connector removed');
    const skipped=await request('/api/integrations/legacy/poll','POST','{}');assert.match(skipped.data.error,/REST has been removed/);
    await app.pollAll();
    assert.equal((await app.db.prepare('SELECT checked_at FROM integrations WHERE id=?').bind('legacy').first()).checked_at,null);
    assert.equal((await request('/api/integrations','POST',JSON.stringify({name:'REST',connector:'mikrotik',mode:'direct',auth:'basic',endpoint:'https://router.internal',credential:secret}))).status,400);
    const edited=await request('/api/integrations/legacy','PATCH',JSON.stringify({name:'Router',connector:'mikrotik-api',mode:'direct',auth:'basic',endpoint:'tcp://192.168.5.1:8728',customer:'School'}));
    assert.equal(edited.status,200);
    const record=await app.db.prepare('SELECT * FROM integrations WHERE id=?').bind('legacy').first();
    assert.equal(record.connector,'mikrotik-api');assert.deepEqual((await decrypt(record.encrypted,config.encryptionKey,'local-admin:legacy')).password,secret.password);
    assert.equal(await app.db.prepare('SELECT * FROM classic_cache WHERE id=?').bind('legacy').first(),null);
  }finally{await app.close();fs.rmSync(dir,{recursive:true,force:true});}
});

test('Frontend Remove sends valid JSON and refreshes the integration inventory',async()=>{
  const source=fs.readFileSync(new URL('../public/app.js',import.meta.url),'utf8');
  const line=source.split('\n').find(line=>line.startsWith('function deleteIntegration(')||line.startsWith('async function deleteIntegration('));
  const calls=[];let refreshed=0,rendered=0,closed=0;
  const nodes=new Map(),$=selector=>{if(!nodes.has(selector))nodes.set(selector,{disabled:false,textContent:''});return nodes.get(selector);};
  const context=vm.createContext({$,vault:[{id:'router',name:'Router'}],classicData:{router:{}},classicOpened:'router',esc:v=>v,
    button:()=>'',showModal:()=>{},closeModal:()=>closed++,toast:()=>{},api:async(...args)=>{calls.push(args);return {deleted:true};},refreshVault:async()=>refreshed++,render:()=>rendered++});
  vm.runInContext(line,context);vm.runInContext("deleteIntegration('router')",context);
  const confirm=[...nodes.values()].find(node=>typeof node.onclick==='function');assert(confirm,'Removal confirmation remains required');
  await confirm.onclick();
  assert.equal(calls[0][0],'integrations/router');assert.equal(calls[0][1],'DELETE');assert.equal(JSON.stringify(calls[0][2]),'{}');
  assert.equal(refreshed,1);assert.equal(rendered,1);assert.equal(closed,1);
});

test('MikroTik settings expose only the native connector and convert legacy HTTP defaults on edit',()=>{
  const source=fs.readFileSync(new URL('../public/app.js',import.meta.url),'utf8');
  assert(!source.includes('<option value="mikrotik"'));
  assert(source.includes('<option value="mikrotik-api"'));
  const functions=['selectConnector','selectNativeTransport','integrationFields','telemetryConnector'].map(name=>source.split('\n').find(line=>line.startsWith('function '+name+'('))).join('\n');
  const nodes=new Map(),$=selector=>{if(!nodes.has(selector))nodes.set(selector,{value:'',style:{}});return nodes.get(selector);};
  $('#f-connector').value='mikrotik-api';$('#f-endpoint').value='https://router.internal/rest';$('#f-customer').value='School';
  const context=vm.createContext({$,document:{querySelector:$},URL});vm.runInContext(functions+'\nselectConnector();',context);
  assert.equal($('#f-endpoint').value,'tcp://router.internal:8728');assert.equal($('#f-customer').value,'School');assert.equal($('#f-auth').value,'basic');
});


test('Add/edit integration requires a dedicated connector and foreground polling skips retired records',async()=>{
  const source=fs.readFileSync(new URL('../public/app.js',import.meta.url),'utf8');
  const functions=['configure','integrationFields','telemetryConnector','pollIntegrations'].map(name=>source.split('\n').find(line=>line.startsWith('function '+name+'(')||line.startsWith('async function '+name+'('))).join('\n');
  const nodes=new Map(),$=selector=>{if(!nodes.has(selector))nodes.set(selector,{value:'',style:{}});return nodes.get(selector);};
  let html='',requests=[];
  const context=vm.createContext({$,document:{querySelector:$},vault:[{id:'old',connector:'generic',endpoint:'http://dns.internal',name:'DNS',customer:'School'},{id:'dns',connector:'adguard'}],
    field:()=>'',secretField:()=>'',customerSelect:value=>'<select>'+value+'</select>',button:()=>'',showModal:value=>html=value,
    backendReady:true,pollRunning:false,workspaceMutation:false,classicData:{},reloadDashboard:async()=>{},refreshLiveViews:()=>{},api:async path=>{requests.push(path);return {status:'Connected',lastSuccess:'now'};}});
  vm.runInContext(functions,context);vm.runInContext("configure('old')",context);
  assert(!html.includes('<option value="generic"'));assert(!html.includes('id="bridge-fields"'));assert(!html.includes('id="header-fields"'));
  assert.match(html,/<select id="f-connector"[^>]*required/);assert.match(html,/<option value="" disabled selected>/);assert(html.includes('School'));
  for(const connector of ['unifi-classic','pangolin','mikrotik-api','adguard'])assert(html.includes('<option value="'+connector+'"'));
  await vm.runInContext('pollIntegrations()',context);assert.deepEqual(requests,['integrations/dns/poll']);
});
