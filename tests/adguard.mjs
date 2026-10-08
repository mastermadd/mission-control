import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import vm from 'node:vm';
import {AdGuardSession,adguardBase,pollAdGuard} from '../lib/adguard.js';
import {LocalDB} from '../db.mjs';
import {encrypt} from '../lib/security.js';
import {passwordHash} from '../auth.mjs';
import {startServer} from '../server.mjs';

const secret={username:'fixture-adguard',password:'FIXTURE-SECRET'};
const status={version:'v0.107.79',running:true,protection_enabled:true,protection_disabled_duration:0,dns_port:53,http_port:80,start_time:Date.now()-3600000,dns_addresses:['DO-NOT-EXPOSE'],password:'DO-NOT-EXPOSE'};
const stats={num_dns_queries:1000,num_blocked_filtering:200,num_replaced_safebrowsing:3,num_replaced_parental:4,num_replaced_safesearch:5,avg_processing_time:0.025,top_clients:[{'DO-NOT-EXPOSE':200}],top_queried_domains:[{'DO-NOT-EXPOSE':900}],top_upstreams_responses:[{'DO-NOT-EXPOSE':100}]};
const fixture=async url=>Response.json(new URL(url).pathname.endsWith('/status')?status:stats);

test('AdGuard reads only status/statistics over HTTP(S), converts units and excludes private records',async()=>{
  const calls=[];
  const session=new AdGuardSession('http://adguard.internal:80',secret,{proxy:true,fetcher:async(url,options)=>{
    calls.push(new URL(url).pathname);assert.equal(options.method,'GET');assert.equal(options.redirect,'manual');assert(options.signal);
    assert.equal(options.headers.Authorization,'Basic '+Buffer.from(secret.username+':'+secret.password).toString('base64'));
    assert.equal(options.headers['P-Access-Token-Id'],'fixture-token-id');return fixture(url);
  }});
  session.secret={...secret,proxyId:'fixture-token-id',proxyToken:'fixture-token'};
  const data=await session.collect();assert.deepEqual(calls,['/control/status','/control/stats']);
  assert.equal(data.server.running,true);assert.equal(data.server.protectionEnabled,true);assert.equal(data.stats.averageProcessingMs,25);
  assert.equal(data.stats.filteringPercent,20);assert.equal(data.stats.queries,1000);assert.equal(data.server.dnsPort,53);
  assert(!JSON.stringify(data).includes('DO-NOT-EXPOSE'));assert(!JSON.stringify(data).includes(secret.password));
  await assert.rejects(session.read('/querylog'),/Read endpoint not allowed/);await assert.rejects(session.read('/protection'),/Read endpoint not allowed/);assert.equal(calls.length,2);
  assert.equal(adguardBase('https://adguard.internal/control/'),'https://adguard.internal/control');
  assert.throws(()=>adguardBase('http://adguard.internal/control/status'),/web URL/);
  assert.throws(()=>adguardBase('http://user:pass@adguard.internal'),/embedded credentials/);
  const old=await new AdGuardSession('http://adguard.internal',secret,{fetcher:async url=>Response.json(new URL(url).pathname.endsWith('/status')?{version:'v0.107.0',protection_enabled:false}:{num_dns_queries:0,num_blocked_filtering:0})}).collect();
  assert.equal(old.server.running,null);assert.equal(old.stats.filteringPercent,0);assert.equal(old.stats.averageProcessingMs,null);
});

test('AdGuard errors identify wrong credentials, TLS, redirects, invalid JSON and incomplete statistics safely',async()=>{
  for(const [code,pattern] of [[401,/authentication failed/],[403,/denied access/],[302,/redirected/],[404,/route not found/]])await assert.rejects(new AdGuardSession('https://adguard.internal',secret,{fetcher:async()=>new Response('DO-NOT-EXPOSE',{status:code})}).collect(),pattern);
  await assert.rejects(new AdGuardSession('https://adguard.internal',secret,{fetcher:async()=>{throw Object.assign(new Error(secret.password),{cause:{code:'DEPTH_ZERO_SELF_SIGNED_CERT'}});}}).collect(),/certificate is untrusted/);
  await assert.rejects(new AdGuardSession('http://adguard.internal',secret,{fetcher:async()=>new Response('<html>Login</html>')}).collect(),/invalid or oversized JSON/);
  await assert.rejects(new AdGuardSession('http://adguard.internal',secret,{fetcher:async url=>Response.json(new URL(url).pathname.endsWith('/status')?status:{error:'DO-NOT-EXPOSE'})}).collect(),/statistics response is incomplete/);
  await assert.rejects(new AdGuardSession('http://adguard.internal',secret,{fetcher:async()=>Response.json([])}).collect(),/invalid response object/);
});

test('AdGuard polls retain stale data, avoid overlaps and discard results after integration deletion',async()=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'mission-adguard-')),db=new LocalDB(path.join(dir,'db.sqlite')),env={DB:db,INTEGRATION_ENCRYPTION_KEY:'ca'.repeat(32)};
  try {
    const encrypted=await encrypt(secret,env.INTEGRATION_ENCRYPTION_KEY,'owner:dns');
    await db.prepare('INSERT INTO integrations (id,owner,connector,name,endpoint,mode,auth,encrypted,status,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)').bind('dns','owner','adguard','DNS','http://adguard.internal','direct','basic',encrypted,'Not tested','now').run();
    const record=await db.prepare('SELECT * FROM integrations WHERE id=?').bind('dns').first();
    const success=await pollAdGuard(env,record,{fetcher:fixture});assert.equal(success.status,'Connected');
    const skipped=await pollAdGuard(env,record,{fetcher:()=>{throw Error('Must not fetch');}});assert.equal(skipped.skipped,true);
    const failed=await pollAdGuard(env,record,{force:true,fetcher:async()=>new Response('',{status:401})});assert.equal(failed.stale,true);assert.deepEqual(failed.data,success.data);assert.equal(failed.lastSuccess,success.lastSuccess);
    const cached=await db.prepare('SELECT snapshot FROM classic_cache WHERE id=?').bind('dns').first();assert(!cached.snapshot.includes('DO-NOT-EXPOSE'));
    let enter,release;const entered=new Promise(resolve=>enter=resolve),hold=new Promise(resolve=>release=resolve);
    const pending=pollAdGuard(env,record,{force:true,fetcher:async url=>{enter();await hold;return fixture(url);}});await entered;
    const overlap=await pollAdGuard(env,record,{force:true,fetcher:()=>{throw Error('Must not overlap');}});assert.equal(overlap.status,'Poll already in progress');
    await db.batch([db.prepare('DELETE FROM classic_cache WHERE id=?').bind('dns'),db.prepare('DELETE FROM integrations WHERE id=?').bind('dns')]);release();
    assert.equal((await pending).status,'Configuration changed; poll discarded');
    assert.equal(await db.prepare('SELECT * FROM classic_cache WHERE id=?').bind('dns').first(),null);
  }finally{db.close();fs.rmSync(dir,{recursive:true,force:true});}
});

test('Authenticated AdGuard flow upgrades generic settings, reuses encrypted credentials, polls in background and deletes cleanly',async()=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'mission-adguard-api-')),config={origin:'http://localhost:8080',username:'admin',password:passwordHash('fixture-admin-password'),encryptionKey:'ab'.repeat(32)};
  const app=startServer(config,{database:path.join(dir,'db.sqlite'),port:0,host:'127.0.0.1',poll:false});await new Promise(resolve=>app.server.once('listening',resolve));
  const originalFetch=globalThis.fetch,base='http://127.0.0.1:'+app.server.address().port;let cookie='',calls=0,deny=false;
  globalThis.fetch=async(url,options)=>{if(String(url).startsWith('http://adguard.internal/')){calls++;return deny?new Response('',{status:401}):fixture(url);}return originalFetch(url,options);};
  async function request(url,method='GET',data){const response=await originalFetch(base+url,{method,headers:{Origin:config.origin,'Content-Type':'application/json',Cookie:cookie},...(data===undefined?{}:{body:JSON.stringify(data)})});return {status:response.status,cookie:response.headers.get('set-cookie'),data:await response.json()};}
  try {
    const login=await request('/auth/login','POST',{username:'admin',password:'fixture-admin-password'});cookie=login.cookie.split(';')[0];
    await request('/api/customers','POST',{name:'School',type:'Education',contact:'IT'});
    const saved=await request('/api/integrations','POST',{name:'DNS',connector:'generic',endpoint:'http://adguard.internal/control/status',mode:'direct',auth:'basic',credential:secret,customer:'School'});const id=saved.data.id;assert(id);
    const settings={name:'DNS',connector:'adguard',endpoint:'http://adguard.internal',mode:'direct',auth:'basic',customer:'School'};
    assert.equal((await request('/api/integrations/'+id,'PATCH',{...settings,auth:'bearer'})).status,400);
    assert.equal((await request('/api/integrations/'+id,'PATCH',settings)).status,200);
    const tested=await request('/api/integrations/'+id+'/test','POST',{});assert.equal(tested.data.status,'Connected');assert.equal(tested.data.data.stats.queries,1000);assert.equal(calls,2);
    await app.pollAll();assert.equal(calls,2);
    const row=await app.db.prepare('SELECT * FROM classic_cache WHERE id=?').bind(id).first();assert(!row.snapshot.includes('DO-NOT-EXPOSE'));
    const listed=await request('/api/integrations');assert.equal(listed.data.integrations[0].connector,'adguard');assert(!JSON.stringify(listed.data).includes(secret.password));
    deny=true;const failed=await request('/api/integrations/'+id+'/test','POST',{});assert.equal(failed.data.stale,true);assert.equal(failed.data.lastSuccess,tested.data.lastSuccess);assert.equal(failed.data.data.server.running,true);
    assert.equal((await request('/api/integrations/'+id+'/data')).data.data.stats.averageProcessingMs,25);
    assert.equal((await request('/api/assets','DELETE',{integrationId:id})).status,403);
    assert.equal((await request('/api/integrations/'+id,'DELETE')).status,200);
    assert.equal(await app.db.prepare('SELECT * FROM classic_cache WHERE id=?').bind(id).first(),null);
    const second=await request('/api/integrations','POST',{...settings,credential:secret});assert(second.data.id);
    assert.equal((await request('/api/customers/0','DELETE',{expectedName:'School'})).status,200);assert.equal((await request('/api/integrations')).data.integrations.length,0);
  }finally{globalThis.fetch=originalFetch;await app.close();fs.rmSync(dir,{recursive:true,force:true});}
});

test('AdGuard frontend joins inventory, customer and network views, and distinguishes failed polls from DNS state',async()=>{
  const source=fs.readFileSync(new URL('../public/app.js',import.meta.url),'utf8');
  const names=['telemetryConnector','adguardAssets','adguardPanel','classicPanel','classicSummary','cacheStale','integrationAssets','operationAlerts','customerIntegrations','selectConnector','integrationFields'];
  const functions=names.map(name=>source.split('\n').find(line=>line.startsWith('function '+name+'('))).join('\n');
  const integration={id:'dns',name:'<School DNS>',connector:'adguard',customer:'School',endpoint:'http://adguard.internal/control',status:'Connected'};
  const snapshot={lastSuccess:new Date().toISOString(),stale:false,data:await new AdGuardSession('http://adguard.internal',secret,{fetcher:fixture}).collect()};
  const nodes=new Map(),$=selector=>{if(!nodes.has(selector))nodes.set(selector,{value:'',style:{}});return nodes.get(selector);};
  const context=vm.createContext({$,document:{querySelector:$},URL,vault:[integration],classicData:{dns:snapshot},state:{alerts:[]},esc:value=>String(value??'').replaceAll('<','&lt;'),panel:(title,html)=>title+html,tag:value=>value,Date});vm.runInContext(functions,context);
  assert.equal(vm.runInContext('integrationAssets()[0].customer',context),'School');assert.equal(vm.runInContext('integrationAssets()[0].live',context),true);
  const html=vm.runInContext("classicPanel('dns')",context);assert(html.includes('AdGuard Home data'));assert(html.includes('&lt;School DNS>'));assert(html.includes('25 ms'));assert(html.includes('1000'));
  assert(vm.runInContext("customerIntegrations('School')",context).includes('&lt;School DNS>'));
  snapshot.data.server.protectionEnabled=false;snapshot.data.server.running=false;
  assert.equal(vm.runInContext('operationAlerts().length',context),2);
  snapshot.stale=true;snapshot.error='Authentication failed';
  assert.equal(vm.runInContext('operationAlerts().length',context),1);assert.match(vm.runInContext('operationAlerts()[0].title',context),/telemetry stale/);
  assert.equal(vm.runInContext('integrationAssets()[0].status',context),'Stopped');
  $('#f-connector').value='adguard';$('#f-endpoint').value='http://adguard.internal/control/status';$('#f-auth').value='bearer';$('#f-mode').value='bridge';$('#f-customer').value='School';
  vm.runInContext('selectConnector()',context);assert.equal($('#f-endpoint').value,'http://adguard.internal');assert.equal($('#f-auth').value,'basic');assert.equal($('#f-mode').value,'direct');assert.equal($('#adguard-help').style.display,'block');assert.equal($('#f-customer').value,'School');
  context.vault=[];assert.equal(vm.runInContext('integrationAssets().length',context),0);
});
