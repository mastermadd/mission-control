import {ApiError} from './security.js';
const text=(value,max,required=false)=>{if(typeof value!=='string'||value.length>max||/[\0]/.test(value)||(required&&!value.trim()))throw new ApiError('Invalid alert or task details.');return value;};
export function alertKey(alert){return alert.live?'integration:'+JSON.stringify([String(alert.integrationId||''),String(alert.id)]):'workspace:'+String(alert.id);}
export function alertSnapshot(value){
 if(!value||!['string','number'].includes(typeof value.id))throw new ApiError('Invalid alert.');
 const live=value.live===true;
 return {id:text(String(value.id),1500,true),title:text(value.title,300,true),source:text(value.source||'',400),severity:value.severity==='critical'?'critical':'warning',detail:text(value.detail||'',2000),live,integrationId:live?text(value.integrationId,128,true):'',customer:text(value.customer||'',200)};
}
export function savedAcknowledgements(data){return Array.isArray(data?.alertAcknowledgements)?data.alertAcknowledgements:[];}
export async function applyAlertAction(db,owner,body){
 if(!['acknowledge','reopen','task'].includes(body.action))throw new ApiError('Unknown alert action.');
 const input=alertSnapshot(body.alert),key=alertKey(input),now=new Date().toISOString();
 for(let attempt=0;attempt<4;attempt++){
  const row=await db.prepare('SELECT data FROM workspaces WHERE owner=?').bind(owner).first();if(!row)throw new ApiError('Workspace not found.',404);
  const data=JSON.parse(row.data),saved=savedAcknowledgements(data),ack=saved.find(a=>a.key===key);let alert=input;
  if(!input.live){const record=data.alerts.find(a=>String(a.id)===input.id);if(!record&&!ack)throw new ApiError('Alert not found.',404);alert=record?alertSnapshot({...record,live:false}):ack.alert;}
  else if(!ack){const integration=await db.prepare('SELECT id FROM integrations WHERE id=? AND owner=?').bind(input.integrationId,owner).first();if(!integration)throw new ApiError('Integration alert not found.',404);}
  let taskId=null,created=false,changed=true;
  data.alertAcknowledgements=saved;
  if(body.action==='acknowledge'){
   if(ack)return {data,changed:false};
   if(saved.length>=500)throw new ApiError('Acknowledgement history is full. Reopen an older alert first.');
   data.alertAcknowledgements=[...saved,{key,alert,acknowledgedAt:now}];
   if(!alert.live){const record=data.alerts.find(a=>String(a.id)===alert.id);if(record)record.ack=true;}
  }else if(body.action==='reopen'){
   const record=!alert.live?data.alerts.find(a=>String(a.id)===alert.id):null;
   changed=!!ack||!!record?.ack;if(!changed)return {data,changed:false};
   data.alertAcknowledgements=saved.filter(a=>a.key!==key);if(record)record.ack=false;
  }else{
   const existing=data.tasks.find(t=>t.alertKey===key);if(existing)return {data,taskId:existing.id,created:false,changed:false};
   if(data.tasks.length>=500)throw new ApiError('Maximum 500 tasks.');
   const title=text(body.task?.title||alert.title,200,true).trim(),agent=text(body.task?.agent||'JARVIS',64,true),description=text(body.task?.description??[alert.source,alert.detail].filter(Boolean).join('\n\n'),4000);
   if(!['JARVIS','Doctor Strange'].includes(agent))throw new ApiError('Choose a valid task assignee.');
   taskId=crypto.randomUUID();created=true;
   data.tasks.push({id:taskId,title,agent,status:'Queued',description,createdAt:now,alertKey:key,alertTitle:alert.title,alertSource:alert.source,alertDetail:alert.detail,alertSeverity:alert.severity,alertId:alert.id,alertIntegrationId:alert.integrationId,customer:alert.customer});
  }
  const verb=body.action==='acknowledge'?'Acknowledged alert':body.action==='reopen'?'Reopened alert':'Created alert task';
  data.activity=[{text:verb+': '+alert.title,time:new Date(now).toLocaleTimeString('en-ZA',{timeZone:'Africa/Johannesburg',hour:'2-digit',minute:'2-digit'})},...data.activity].slice(0,12);
  const encoded=JSON.stringify(data);if(encoded.length>900000)throw new ApiError('Workspace storage limit reached.');
  const written=await db.prepare('UPDATE workspaces SET data=?,updated_at=? WHERE owner=? AND data=?').bind(encoded,now,owner,row.data).run();
  if(written.meta.changes)return {data,taskId,created,changed,audit:verb,name:alert.title};
 }
 throw new ApiError('Workspace changed while saving. Please try again.',409);
}
