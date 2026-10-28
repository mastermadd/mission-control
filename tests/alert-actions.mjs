import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import os from 'node:os';import path from 'node:path';
import {startServer} from '../server.mjs';import {passwordHash} from '../auth.mjs';import {applyAlertAction,alertKey} from '../lib/alert-actions.js';
test('Acknowledgements and alert tasks are authenticated, persistent, isolated, idempotent and preserve source context',async()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'mc-alerts-')),database=path.join(dir,'db.sqlite'),config={origin:'http://localhost:8080',username:'admin',password:passwordHash('fixture-password'),encryptionKey:'ab'.repeat(32),owner:'owner'};let app=startServer(config,{database,port:0,host:'127.0.0.1',poll:false});await new Promise(r=>app.server.once('listening',r));let base='http://127.0.0.1:'+app.server.address().port,cookie='';
 async function request(route,method='GET',body,origin=config.origin){const r=await fetch(base+'/api/'+route,{method,headers:{Cookie:cookie,Origin:origin,'Content-Type':'application/json'},...(body===undefined?{}:{body:JSON.stringify(body)})});return {status:r.status,data:await r.json()}}
 const alert={id:'device-native',live:true,integrationId:'integration-one',customer:'School',title:'AP <Library> disconnected',source:'School · Campus',severity:'warning',detail:'Check its power and uplink.',password:'NEVER-RETURN'};
 try{
  assert.equal((await request('alerts/actions','POST',{action:'acknowledge',alert})).status,401);
  const login=await fetch(base+'/auth/login',{method:'POST',headers:{Origin:config.origin,'Content-Type':'application/json'},body:JSON.stringify({username:'admin',password:'fixture-password'})});cookie=login.headers.get('set-cookie').split(';')[0];
  const workspace={customers:[{name:'School'}],assets:[],alerts:[{id:7,title:'Manual alert',source:'Operations',severity:'critical',detail:'Manual context',ack:false}],tasks:[],activity:[]};assert.equal((await request('workspace','PUT',workspace)).status,200);
  await app.db.prepare('INSERT INTO integrations (id,owner,connector,name,endpoint,mode,auth,encrypted,status,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)').bind('integration-one','owner','unifi-classic','School network','https://fixture.invalid','direct','basic','encrypted-fixture','Not tested',new Date().toISOString()).run();
  assert.equal((await request('alerts/actions','POST',{action:'acknowledge',alert},'https://evil.invalid')).status,403);
  let result=await request('alerts/actions','POST',{action:'acknowledge',alert});assert.equal(result.status,200,JSON.stringify(result));assert.equal(result.data.data.alertAcknowledgements.length,1);assert(!JSON.stringify(result.data).includes('NEVER-RETURN'));const acknowledgedAt=result.data.data.alertAcknowledgements[0].acknowledgedAt;
  result=await request('alerts/actions','POST',{action:'acknowledge',alert});assert.equal(result.data.changed,false);assert.equal(result.data.data.alertAcknowledgements[0].acknowledgedAt,acknowledgedAt);
  await request('workspace','PUT',workspace);assert.equal((await request('workspace')).data.data.alertAcknowledgements.length,1,'legacy workspace save preserves acknowledgements');
  await assert.rejects(()=>applyAlertAction(app.db,'another-owner',{action:'acknowledge',alert}),/Workspace not found/);
  assert.equal((await request('alerts/actions','POST',{action:'acknowledge',alert:{...alert,integrationId:'missing'}})).status,404);
  const task={title:'Inspect Library AP',agent:'Doctor Strange',description:'Check PoE and the uplink.'};const duplicate=await Promise.all([request('alerts/actions','POST',{action:'task',alert,task}),request('alerts/actions','POST',{action:'task',alert,task})]);assert(duplicate.every(r=>r.status===200));
  result=await request('workspace');const tasks=result.data.data.tasks;assert.equal(tasks.length,1);assert.equal(tasks[0].alertKey,alertKey(alert));assert.equal(tasks[0].alertDetail,alert.detail);assert.equal(tasks[0].alertSource,alert.source);assert.equal(tasks[0].description,task.description);assert.equal(tasks[0].status,'Queued');assert.equal(result.data.data.alertAcknowledgements.length,1,'task action does not alter acknowledgement');
  assert.equal((await request('alerts/actions','POST',{action:'reopen',alert})).data.data.alertAcknowledgements.length,0);
  const manual=workspace.alerts[0];result=await request('alerts/actions','POST',{action:'acknowledge',alert:manual});assert.equal(result.data.data.alerts[0].ack,true);
  result=await request('alerts/actions','POST',{action:'reopen',alert:manual});assert.equal(result.data.data.alerts[0].ack,false);
  await request('alerts/actions','POST',{action:'acknowledge',alert});await app.close();app=startServer(config,{database,port:0,host:'127.0.0.1',poll:false});await new Promise(r=>app.server.once('listening',r));base='http://127.0.0.1:'+app.server.address().port;
  result=await request('workspace');assert.equal(result.status,200);assert.equal(result.data.data.alertAcknowledgements.length,1);assert.equal(result.data.data.tasks.length,1,'task and acknowledgement survive restart');
 }finally{await app.close();fs.rmSync(dir,{recursive:true,force:true})}
});
