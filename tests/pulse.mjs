import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import vm from 'node:vm';
import {PulseSession,pulseBase,sanitizePulse,pollPulse} from '../lib/pulse.js';
import {LocalDB} from '../db.mjs';
import {encrypt,decrypt} from '../lib/security.js';
import {passwordHash} from '../auth.mjs';
import {startServer} from '../server.mjs';
const secret={key:'FIXTURE-PULSE-TOKEN'};
const hidden='DO-NOT-EXPOSE';
const legacy=()=>({lastUpdate:Date.now(),nodes:[{id:'pve',name:'<PVE>',status:'online',cpu:0.25,memory:{used:4,total:8,usage:50},disk:{used:20,total:100,usage:20},uptime:3600,pveVersion:'9.0',host:hidden,password:hidden}],vms:[{id:'vm-100',vmid:100,name:'App',node:'pve',status:'stopped',cpu:0,disk:{used:0,total:100,usage:-1}}],containers:[{id:'ct-101',vmid:101,name:'DNS',node:'pve',status:'running'}],storage:[{id:'pve/local',name:'local',node:'pve',status:'active',used:30,total:100,usage:30,path:hidden}],activeAlerts:[{id:'cpu-alert',resourceName:'PVE',type:'cpu',level:'warning',message:hidden,metadata:{password:hidden},acknowledged:false}],metrics:{token:hidden}});
const unified=()=>({lastUpdate:new Date().toISOString(),resources:[{id:'node-1',name:'PVE',type:'agent',platformType:'proxmox-pve',status:'online',cpu:{current:25},memory:{used:4,total:8,current:50},disk:{used:20,total:100,current:20},health:{verdict:'ok'},proxmox:{hostUrl:hidden,password:hidden,pveVersion:'9.0',nodeName:'pve-node',instance:'School cluster'}},{id:'vm-100',name:'VM',type:'vm',platformType:'proxmox-pve',status:'offline',health:{verdict:'off'},proxmox:{vmid:100},disk:{used:0,total:100,current:-1}},{id:'ct-101',name:'LXC',type:'system-container',platformType:'proxmox-pve',status:'running',health:{verdict:'stale'},memory:{current:-1,used:0,total:10}},{id:'storage',name:'local',type:'storage',sources:['proxmox'],status:'online'},{id:'pbs',name:'PBS',type:'agent',platformType:'proxmox-pbs',sources:['proxmox']},{id:'docker',type:'container',platformType:'docker'},{id:'nas',type:'storage',platformType:'truenas'}],activeAlerts:[]});

test('Pulse reads only authenticated state, sanitizes legacy and unified PVE resources and preserves unknown/stopped states',async()=>{
 const calls=[];const s=new PulseSession('http://pulse.internal:7655/api', {...secret,proxyId:'proxy-id',proxyToken:'proxy-token'},{proxy:true,fetcher:async(url,o)=>{calls.push(url);assert.equal(o.method,'GET');assert.equal(o.redirect,'manual');assert(o.signal);assert.equal(o.headers.Authorization,'Bearer '+secret.key);assert.equal(o.headers['P-Access-Token-Id'],'proxy-id');return Response.json(legacy());}});
 const d=await s.collect();assert.deepEqual(calls,['http://pulse.internal:7655/api/state']);assert.equal(d.summary.nodes,1);assert.equal(d.summary.vms,1);assert.equal(d.summary.containers,1);assert.equal(d.summary.storage,1);assert.equal(d.resources[0].cpuPercent,25);assert.equal(d.resources[1].disk.percent,null);assert.equal(d.resources[1].status,'Stopped');assert.equal(d.sourceStale,false);assert(!JSON.stringify(d).includes(hidden));
 await assert.rejects(s.read('/config/nodes'),/Read endpoint not allowed/);await assert.rejects(s.read('/state?raw=1'),/Read endpoint not allowed/);assert.equal(calls.length,1);
 const modern=sanitizePulse(unified());assert.equal(modern.resources.length,4);assert.equal(modern.resources[0].cpuPercent,25);assert.equal(modern.resources[0].node,'pve-node');assert.equal(modern.resources[0].instance,'School cluster');assert.equal(modern.resources[1].status,'Stopped');assert.equal(modern.resources[1].disk.percent,null);assert.equal(modern.resources[2].status,'Stale');assert.equal(modern.resources[2].memory.percent,null);assert(!JSON.stringify(modern).includes(hidden));
 const old=legacy();old.lastUpdate=Date.now()-180000;assert.equal(sanitizePulse(old).sourceStale,true);delete old.lastUpdate;assert.equal(sanitizePulse(old).sourceStale,true);
 assert.equal(pulseBase('https://pulse.internal/api/'),'https://pulse.internal/api');assert.throws(()=>pulseBase('http://pulse.internal/api/state'),/base URL/);assert.throws(()=>pulseBase('http://u:p@pulse.internal'),/embedded credentials/);
 assert.throws(()=>sanitizePulse({status:'healthy'}),/incomplete/);assert.throws(()=>sanitizePulse({resources:{}}),/incomplete/);assert.throws(()=>sanitizePulse({...legacy(),activeAlerts:{}}),/invalid/);
});

test('Pulse handles denied access, redirects, invalid JSON, TLS and timeouts without exposing secrets',async()=>{
 for(const [status,pattern] of [[401,/authentication failed/],[403,/monitoring:read/],[302,/redirected/],[404,/not found/],[500,/HTTP 500/]])await assert.rejects(new PulseSession('https://pulse.internal',secret,{fetcher:async()=>new Response(hidden,{status})}).collect(),pattern);
 await assert.rejects(new PulseSession('https://pulse.internal',secret,{fetcher:async()=>new Response('<html>'+hidden+'</html>')}).collect(),/invalid or oversized JSON/);
 for(const [code,pattern] of [['DEPTH_ZERO_SELF_SIGNED_CERT',/certificate/],['ENOTFOUND',/resolved/],['ETIMEDOUT',/timed out/]])await assert.rejects(new PulseSession('https://pulse.internal',secret,{fetcher:async()=>{throw Object.assign(Error(secret.key),{cause:{code}});}}).collect(),pattern);
 await assert.rejects(new PulseSession('http://pulse.internal',secret,{fetcher:async()=>new Response('x'.repeat(8*1024*1024+1))}).collect(),/oversized/);
});

test('Pulse cache leases prevent overlapping polls, preserve last success on failure and fence late edits/deletes',async()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'mission-pulse-')),db=new LocalDB(path.join(dir,'db.sqlite')),env={DB:db,INTEGRATION_ENCRYPTION_KEY:'ac'.repeat(32)};
 try{
 const encrypted=await encrypt(secret,env.INTEGRATION_ENCRYPTION_KEY,'owner:pulse');
 await db.prepare('INSERT INTO integrations (id,owner,connector,name,endpoint,mode,auth,encrypted,status,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)').bind('pulse','owner','pulse','PVE','http://pulse.internal/api','direct','bearer',encrypted,'Not tested','now').run();
 const record=await db.prepare('SELECT * FROM integrations WHERE id=?').bind('pulse').first();
 const success=await pollPulse(env,record,{fetcher:async()=>Response.json(legacy())});assert.equal(success.status,'Connected');
 assert.equal((await pollPulse(env,record,{fetcher:()=>{throw Error('not due');}})).skipped,true);
 const upstreamOld=legacy();upstreamOld.lastUpdate=Date.now()-180000;const upstreamStale=await pollPulse(env,record,{force:true,fetcher:async()=>Response.json(upstreamOld)});assert.equal(upstreamStale.stale,true);assert.equal(upstreamStale.data.resources[0].status,'Connected');
 const recovered=await pollPulse(env,record,{force:true,fetcher:async()=>Response.json(legacy())});
 const failed=await pollPulse(env,record,{force:true,fetcher:async()=>new Response('',{status:401})});assert.equal(failed.stale,true);assert.equal(failed.lastSuccess,recovered.lastSuccess);assert.deepEqual(failed.data,recovered.data);
 for(const mutation of ['edit','delete']){
 const current=await db.prepare('SELECT * FROM integrations WHERE id=?').bind('pulse').first();let enter,release;const entered=new Promise(r=>enter=r),hold=new Promise(r=>release=r);
 const pending=pollPulse(env,current,{force:true,fetcher:async()=>{enter();await hold;return Response.json(legacy());}});await entered;
 assert.equal((await pollPulse(env,current,{force:true,fetcher:()=>{throw Error('overlap');}})).status,'Poll already in progress');
 if(mutation==='edit')await db.batch([db.prepare('UPDATE integrations SET revision=revision+1 WHERE id=?').bind('pulse'),db.prepare('DELETE FROM classic_cache WHERE id=?').bind('pulse')]);else await db.batch([db.prepare('DELETE FROM classic_cache WHERE id=?').bind('pulse'),db.prepare('DELETE FROM integrations WHERE id=?').bind('pulse')]);
 release();assert.equal((await pending).status,'Configuration changed; poll discarded');assert.equal(await db.prepare('SELECT * FROM classic_cache WHERE id=?').bind('pulse').first(),null);
 }
 }finally{db.close();fs.rmSync(dir,{recursive:true,force:true});}
});

test('Pulse authenticated CRUD keeps credentials backend-only, polls in background and cascades customer deletion',async()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'mission-pulse-api-')),config={origin:'http://localhost:8080',username:'admin',password:passwordHash('fixture-admin-password'),encryptionKey:'ad'.repeat(32)};
 const app=startServer(config,{database:path.join(dir,'db.sqlite'),port:0,host:'127.0.0.1',poll:false});await new Promise(r=>app.server.once('listening',r));
 const originalFetch=globalThis.fetch,base='http://127.0.0.1:'+app.server.address().port;let cookie='',calls=0,deny=false;
 globalThis.fetch=async(url,o)=>{if(String(url).startsWith('http://pulse.internal/')){calls++;assert.equal(o.headers.Authorization,'Bearer '+secret.key);return deny?new Response('',{status:403}):Response.json(legacy());}return originalFetch(url,o);};
 async function request(url,method='GET',data){const response=await originalFetch(base+url,{method,headers:{Origin:config.origin,'Content-Type':'application/json',Cookie:cookie},...(data===undefined?{}:{body:JSON.stringify(data)})});return {status:response.status,cookie:response.headers.get('set-cookie'),data:await response.json()};}
 try{
 const login=await request('/auth/login','POST',{username:'admin',password:'fixture-admin-password'});cookie=login.cookie.split(';')[0];await request('/api/customers','POST',{name:'School',type:'Education',contact:'IT'});
 const settings={name:'PVE',connector:'pulse',endpoint:'http://pulse.internal',mode:'direct',auth:'bearer',customer:'School'};
 assert.equal((await request('/api/integrations','POST',{...settings,auth:'basic',credential:secret})).status,400);
 const saved=await request('/api/integrations','POST',{...settings,credential:secret});assert.equal(saved.status,200);const id=saved.data.id;
 const tested=await request('/api/integrations/'+id+'/test','POST',{});assert.equal(tested.data.status,'Connected');assert.equal(tested.data.data.resources.length,4);assert.equal(calls,1);
 await app.pollAll();assert.equal(calls,1);await app.db.prepare('UPDATE classic_cache SET next_due=0 WHERE id=?').bind(id).run();await app.pollAll();assert.equal(calls,2);
 assert.equal((await request('/api/integrations/'+id,'PATCH',{...settings,name:'School PVE'})).status,200);const row=await app.db.prepare('SELECT * FROM integrations WHERE id=?').bind(id).first();assert.equal((await decrypt(row.encrypted,config.encryptionKey,'local-admin:'+id)).key,secret.key);assert(!row.encrypted.includes(secret.key));
 for(const url of ['/api/integrations','/api/integrations/'+id+'/data']){const result=await request(url);assert(!JSON.stringify(result.data).includes(secret.key));assert(!JSON.stringify(result.data).includes(hidden));}
 deny=true;const failed=await request('/api/integrations/'+id+'/test','POST',{});assert.equal(failed.data.stale,true);assert(failed.data.lastSuccess);assert.equal(failed.data.data.resources[0].status,'Connected');
 assert.equal((await request('/api/assets','DELETE',{integrationId:id})).status,403);
 assert.equal((await request('/api/integrations/'+id,'DELETE')).status,200);assert.equal(await app.db.prepare('SELECT * FROM classic_cache WHERE id=?').bind(id).first(),null);
 const second=await request('/api/integrations','POST',{...settings,credential:secret});assert(second.data.id);await request('/api/integrations/'+second.data.id+'/test','POST',{});
 assert.equal((await request('/api/customers/0','DELETE',{expectedName:'School'})).status,200);assert.equal((await request('/api/integrations')).data.integrations.length,0);assert.equal(await app.db.prepare('SELECT * FROM classic_cache WHERE id=?').bind(second.data.id).first(),null);
 }finally{globalThis.fetch=originalFetch;await app.close();fs.rmSync(dir,{recursive:true,force:true});}
});

test('Pulse frontend joins customer inventory/data/alerts and auto-selects token authentication without rebuilding forms',async()=>{
 const source=fs.readFileSync(new URL('../public/app.js',import.meta.url),'utf8');const names=['telemetryConnector','pulseAssets','pulsePanel','classicPanel','classicSummary','cacheStale','integrationAssets','operationAlerts','customerIntegrations','selectConnector','integrationFields','customerStatus'];
 const functions=names.map(name=>source.split('\n').find(line=>line.startsWith('function '+name+'('))).join('\n');
 const i={id:'pulse',name:'School PVE',connector:'pulse',customer:'School',endpoint:'http://pulse.internal/api',status:'Connected'},snapshot={lastSuccess:new Date().toISOString(),stale:false,data:sanitizePulse(legacy())};
 const nodes=new Map(),$=s=>{if(!nodes.has(s))nodes.set(s,{value:'',style:{}});return nodes.get(s);};const context=vm.createContext({$,document:{querySelector:$},URL,Date,vault:[i],classicData:{pulse:snapshot},state:{alerts:[]},esc:v=>String(v??'').replaceAll('<','&lt;'),panel:(title,body)=>title+body,tag:v=>v});vm.runInContext(functions,context);
 assert.equal(vm.runInContext('integrationAssets().length',context),4);assert.equal(vm.runInContext('integrationAssets()[0].customer',context),'School');assert.equal(vm.runInContext('integrationAssets()[1].status',context),'Stopped');
 const html=vm.runInContext("classicPanel('pulse')",context);assert(html.includes('Pulse / Proxmox PVE'));assert(html.includes('&lt;PVE>'));assert(html.includes('25%'));assert(html.includes('Pulse monitoring updated'));assert(vm.runInContext("customerIntegrations('School')",context).includes('School PVE'));
 assert.equal(vm.runInContext('operationAlerts().length',context),1);snapshot.stale=true;assert.equal(vm.runInContext('operationAlerts().length',context),1);assert.match(vm.runInContext('operationAlerts()[0].title',context),/telemetry stale/);assert.equal(vm.runInContext('integrationAssets()[0].status',context),'Connected');
 snapshot.stale=false;snapshot.data.sourceStale=true;assert.equal(vm.runInContext("customerStatus({name:'School'})",context),'Attention');
 $('#f-connector').value='pulse';$('#f-endpoint').value='http://pulse.internal/api';$('#f-auth').value='basic';$('#f-customer').value='School';vm.runInContext('selectConnector()',context);assert.equal($('#f-auth').value,'bearer');assert.equal($('#f-mode').value,'direct');assert.equal($('#pulse-help').style.display,'block');assert.equal($('#f-customer').value,'School');assert(source.includes('<option value="pulse"'));
 context.vault=[];assert.equal(vm.runInContext('integrationAssets().length',context),0);
});
