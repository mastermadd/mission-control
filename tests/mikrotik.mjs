import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import vm from 'node:vm';
import {MikroTikSession,mikrotikBase,pollMikroTik} from '../lib/mikrotik.js';
import {LocalDB} from '../db.mjs';
import {encrypt} from '../lib/security.js';
import {passwordHash} from '../auth.mjs';
import {startServer} from '../server.mjs';

const secret = {username:'fixture-reader',password:'FIXTURE-SECRET'};
const fixtures = {
  '/rest/system/identity':[{name:'JDLN Router',password:'DO-NOT-EXPOSE'}],
  '/rest/system/resource':[{version:'7.15.1 (stable)',uptime:'1w2d3h', 'board-name':'RB4011', 'cpu-load':'15', 'total-memory':'1024', 'free-memory':'256', 'architecture-name':'arm',secret:'DO-NOT-EXPOSE'}],
  '/rest/interface':[{name:'ether1',type:'ether',running:'true',disabled:'false','actual-mtu':'1500','rx-byte':'12345','tx-byte':'67890','mac-address':'DO-NOT-EXPOSE',password:'DO-NOT-EXPOSE'}, {name:'ether2',running:'false',disabled:'true'}, {name:'other',running:'unknown',disabled:'unknown'}]
};
const fetcher = async url => Response.json(fixtures[new URL(url).pathname]);

test('RouterOS 7.15.1 REST reads only allowed endpoints and whitelists string-valued telemetry', async () => {
  const calls = [];
  const session = new MikroTikSession('https://router.internal', secret, {fetcher:async (url, options) => {
    calls.push(url);
    assert.equal(options.method,'GET');
    assert.equal(options.redirect,'manual');
    assert.equal(options.headers.Authorization,'Basic '+Buffer.from('fixture-reader:FIXTURE-SECRET').toString('base64'));
    assert(options.signal);
    return fetcher(url);
  }});
  const data = await session.collect();
  assert.equal(calls.length,3);
  assert.equal(data.router.cpuLoad,15);
  assert.equal(data.router.memoryUsage,75);
  assert.equal(data.router.version,'7.15.1 (stable)');
  assert.equal(data.interfaces[0].rxBytes,12345);
  assert.equal(data.interfaces[0].running,true);
  assert.equal(data.interfaces[1].disabled,true);
  assert.equal(data.interfaces[2].running,null);
  assert(!JSON.stringify(data).includes('DO-NOT-EXPOSE'));
  await assert.rejects(session.read('/system/reboot'),/Read endpoint not allowed/);
  assert.equal(calls.length,3);
  assert.equal(mikrotikBase('http://192.168.5.1:8080/rest/'),'http://192.168.5.1:8080/rest');
  assert.throws(() => mikrotikBase('https://router.internal:8729'),/not API ports/);
  assert.throws(() => mikrotikBase('https://router.internal/rest/ip/address'),/base URL/);
});

test('MikroTik errors distinguish TLS, credentials, permissions, redirects and invalid data without leaking errors', async () => {
  for (const [status,message] of [[401,/authentication failed/],[403,/read and rest-api/],[302,/redirect/],[404,/endpoint not found/]]) {
    const session = new MikroTikSession('https://router.internal', secret,{fetcher:async()=>new Response('DO-NOT-EXPOSE',{status})});
    await assert.rejects(session.collect(),message);
  }
  for (const [code,message] of [['DEPTH_ZERO_SELF_SIGNED_CERT',/certificate is untrusted/],['ECONNREFUSED',/refused/],['ENOTFOUND',/resolved/],['ETIMEDOUT',/timed out/]]) {
    await assert.rejects(new MikroTikSession('https://router.internal',secret,{fetcher:async()=>{throw Object.assign(new Error('FIXTURE-SECRET'),{cause:{code}});}}).collect(),message);
  }
  await assert.rejects(new MikroTikSession('https://router.internal',secret,{fetcher:async()=>new Response('<html>Login</html>')}).collect(),/invalid or oversized JSON/);
  await assert.rejects(new MikroTikSession('https://router.internal',secret,{fetcher:async()=>Response.json({error:403})}).collect(),/invalid record list/);
});

test('MikroTik polling retains last success on failure, prevents overlaps and discards writes after edits', async () => {
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'mission-mikrotik-')),db=new LocalDB(path.join(dir,'db.sqlite'));
  const env={DB:db,INTEGRATION_ENCRYPTION_KEY:'ac'.repeat(32)};
  try {
    const encrypted=await encrypt(secret,env.INTEGRATION_ENCRYPTION_KEY,'owner:router');
    await db.prepare('INSERT INTO integrations (id,owner,connector,name,endpoint,mode,auth,encrypted,status,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)').bind('router','owner','mikrotik','Router','https://router.internal','direct','basic',encrypted,'Not tested','now').run();
    const record=await db.prepare('SELECT * FROM integrations WHERE id=?').bind('router').first();
    const now=Date.now();
    const success=await pollMikroTik(env,record,{fetcher,now});
    assert.equal(success.status,'Connected');
    assert.equal(success.stale,false);
    assert(!JSON.stringify(success).includes(secret.password));
    const skipped=await pollMikroTik(env,record,{now:now+1000,fetcher:()=>{throw Error('Must not fetch');}});
    assert.equal(skipped.skipped,true);
    const failure=await pollMikroTik(env,record,{force:true,now:now+2000,fetcher:async()=>new Response('',{status:403})});
    assert.equal(failure.stale,true);
    assert.equal(failure.lastSuccess,success.lastSuccess);
    assert.deepEqual(failure.data,success.data);
    let entered,release;
    const reached=new Promise(resolve=>entered=resolve),hold=new Promise(resolve=>release=resolve);
    const pending=pollMikroTik(env,record,{force:true,now:now+3000,fetcher:async url=>{entered();await hold;return fetcher(url);}});
    await reached;
    const overlap=await pollMikroTik(env,record,{force:true,now:now+4000,fetcher:()=>{throw Error('Must not overlap');}});
    assert.equal(overlap.skipped,true);
    assert.equal(overlap.status,'Poll already in progress');
    await db.prepare('UPDATE integrations SET revision=revision+1 WHERE id=?').bind('router').run();
    await db.prepare('DELETE FROM classic_cache WHERE id=?').bind('router').run();
    release();
    const discarded=await pending;
    assert.equal(discarded.status,'Configuration changed; poll discarded');
    assert.equal(await db.prepare('SELECT * FROM classic_cache WHERE id=?').bind('router').first(),null);
  } finally {db.close();fs.rmSync(dir,{recursive:true,force:true});}
});

test('MikroTik frontend joins customer inventory, network views and stale telemetry alerts', () => {
  const source=fs.readFileSync(new URL('../public/app.js',import.meta.url),'utf8');
  const names=['telemetryConnector','mikrotikAssets','mikrotikPanel','classicPanel','classicSummary','cacheStale','integrationAssets','operationAlerts','customerIntegrations'];
  const functions=names.map(name=>source.split('\n').find(line=>line.startsWith('function '+name+'('))).join('\n');
  const integration={id:'router',name:'Router API',connector:'mikrotik',customer:'School',endpoint:'https://router.internal',status:'Connected'};
  const snapshot={lastSuccess:new Date().toISOString(),stale:false,data:{router:{name:'<Router>',model:'RB4011',version:'7.15.1',uptime:'1w2d',cpuLoad:15,memoryUsage:75},interfaces:[{name:'ether1',running:true,disabled:false,rxBytes:12345,txBytes:67890}]}};
  const context=vm.createContext({vault:[integration],classicData:{router:snapshot},state:{alerts:[]},esc:value=>String(value??'').replaceAll('<','&lt;'),panel:(title,html)=>title+html,tag:value=>value,Date});
  vm.runInContext(functions,context);
  const assets=vm.runInContext('integrationAssets()',context);
  assert.equal(assets[0].customer,'School');
  assert.equal(assets[0].integrationId,'router');
  assert.equal(assets[0].live,true);
  assert.equal(assets[0].status,'Connected');
  const html=vm.runInContext("classicPanel('router')",context);
  assert(html.includes('MikroTik data'));
  assert(html.includes('&lt;Router>'));
  assert(html.includes('12345'));
  assert(vm.runInContext("customerIntegrations('School')",context).includes('Router API'));
  snapshot.stale=true;snapshot.error='Request timed out';
  assert.equal(vm.runInContext('integrationAssets()[0].status',context),'Connected');
  assert.equal(vm.runInContext('integrationAssets()[0].stale',context),true);
  assert.equal(vm.runInContext('operationAlerts()[0].title',context),'Router API · telemetry stale');
  context.vault=[];
  assert.equal(vm.runInContext('integrationAssets().length',context),0);
});

test('Switching to MikroTik selects Basic authentication, preserves customer and hides other connector setup', () => {
  const source=fs.readFileSync(new URL('../public/app.js',import.meta.url),'utf8');
  const functions=['selectConnector','integrationFields'].map(name=>source.split('\n').find(line=>line.startsWith('function '+name+'('))).join('\n');
  const nodes=new Map();
  const $=selector=>{if(!nodes.has(selector))nodes.set(selector,{value:'',style:{}});return nodes.get(selector);};
  $('#f-connector').value='mikrotik';$('#f-endpoint').value='https://router.internal/rest/system/resource';
  $('#f-mode').value='bridge';$('#f-auth').value='bearer';$('#f-customer').value='School';
  const context=vm.createContext({$,document:{querySelector:$},URL});
  vm.runInContext(functions+'\nselectConnector();',context);
  assert.equal($('#f-endpoint').value,'https://router.internal');
  assert.equal($('#f-auth').value,'basic');
  assert.equal($('#f-mode').value,'direct');
  assert.equal($('#f-customer').value,'School');
  assert.equal($('#f-auth').disabled,true);
  assert.equal($('#basic-fields').style.display,'block');
  assert.equal($('#mikrotik-help').style.display,'block');
  assert.equal($('#classic-help').style.display,'none');
  assert.equal($('#pangolin-fields').style.display,'none');
  $('#f-connector').value='generic';
  vm.runInContext('integrationFields();',context);
  assert.equal($('#f-auth').disabled,false);
  assert.equal($('#mikrotik-help').style.display,'none');
});

test('Authenticated API upgrades an existing integration, polls router data and cascades deletion', async () => {
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'mission-mikrotik-api-'));
  const config={origin:'http://localhost:8080',username:'admin',password:passwordHash('fixture-admin-password'),encryptionKey:'bc'.repeat(32)};
  const app=startServer(config,{database:path.join(dir,'db.sqlite'),port:0,host:'127.0.0.1',poll:false});
  await new Promise(resolve=>app.server.once('listening',resolve));
  const base='http://127.0.0.1:'+app.server.address().port,originalFetch=globalThis.fetch;
  let session='',routerCalls=0,deny=false;
  globalThis.fetch=async (url,options)=>{
    if (String(url).startsWith('https://router.internal/')) {routerCalls++;return deny?new Response('',{status:401}):fetcher(url);}
    return originalFetch(url,options);
  };
  async function request(url,method='GET',body){const response=await originalFetch(base+url,{method,headers:{Origin:config.origin,'Content-Type':'application/json',Cookie:session},...(body===undefined?{}:{body:JSON.stringify(body)})});return {response,data:await response.json()};}
  try {
    const login=await request('/auth/login','POST',{username:'admin',password:'fixture-admin-password'});
    session=login.response.headers.get('set-cookie').split(';')[0];
    await request('/api/customers','POST',{name:'School',type:'Education',contact:'IT'});
    const saved=await request('/api/integrations','POST',{name:'Router',connector:'generic',endpoint:'https://router.internal/rest/system/resource',mode:'direct',auth:'basic',customer:'School',credential:secret});
    assert.equal(saved.response.status,200);
    const id=saved.data.id;
    assert(id);
    const invalid=await request('/api/integrations/'+id,'PATCH',{name:'Router',connector:'mikrotik',endpoint:'https://router.internal:8729',mode:'direct',auth:'basic',customer:'School'});
    assert.equal(invalid.response.status,400);
    assert.match(invalid.data.error,/not API ports/);
    const edited=await request('/api/integrations/'+id,'PATCH',{name:'Router',connector:'mikrotik',endpoint:'https://router.internal',mode:'direct',auth:'basic',customer:'School'});
    assert.equal(edited.response.status,200);
    const list=await request('/api/integrations');
    assert.equal(list.data.integrations[0].connector,'mikrotik');
    assert.equal(list.data.integrations[0].endpoint,'https://router.internal/rest');
    assert(!JSON.stringify(list.data).includes(secret.password));
    const tested=await request('/api/integrations/'+id+'/test','POST',{});
    assert.equal(tested.data.status,'Connected');
    assert.equal(tested.data.data.router.name,'JDLN Router');
    assert.equal(routerCalls,3);
    await app.pollAll();
    assert.equal(routerCalls,3,'Background poll respects the existing 60-second cache cadence');
    deny=true;
    const failed=await request('/api/integrations/'+id+'/test','POST',{});
    assert.equal(failed.data.stale,true);
    assert.equal(failed.data.data.router.name,'JDLN Router');
    assert.match(failed.data.error,/authentication failed/);
    const cached=await request('/api/integrations/'+id+'/data');
    assert.equal(cached.data.lastSuccess,tested.data.lastSuccess);
    assert(!JSON.stringify(cached.data).includes(secret.password));
    assert.equal((await request('/api/assets','DELETE',{integrationId:id})).response.status,403);
    assert.equal((await request('/api/customers/0','DELETE',{expectedName:'School'})).response.status,200);
    assert.equal((await request('/api/integrations')).data.integrations.length,0);
    assert.equal(await app.db.prepare('SELECT * FROM classic_cache WHERE id=?').bind(id).first(),null);
  } finally {globalThis.fetch=originalFetch;await app.close();fs.rmSync(dir,{recursive:true,force:true});}
});
