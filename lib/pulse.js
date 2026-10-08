import {ApiError,endpoint,cleanSecret,proxyHeaders,smallJson} from './security.js';
import {classicView} from './unifi-classic.js';
import {decrypt} from './security.js';

export class PulseError extends Error {}
const text=v=>typeof v==='string'?v.slice(0,256):null;
const number=v=>typeof v==='number'&&Number.isFinite(v)&&v>=0?v:null;
const percent=v=>number(v)!==null&&v<=100?Math.round(v*100)/100:null;
const time=v=>{const n=typeof v==='number'?v:typeof v==='string'?Date.parse(v):NaN;return Number.isFinite(n)&&n>0&&n<=8640000000000000?new Date(n).toISOString():null;};
export function pulseBase(base){const u=new URL(endpoint(base));if(!['/','/api','/api/'].includes(u.pathname))throw new ApiError('Use the Pulse server base URL, optionally ending in /api.');return u.origin+'/api';}
function usage(v,legacy=false){if(!v||typeof v!=='object')return {used:null,total:null,percent:null};const unknown=v.usageUnavailable===true||(typeof (legacy?v.usage:v.current)==='number'&&(legacy?v.usage:v.current)<0);const used=unknown?null:number(v.used),total=number(v.total);return {used,total,percent:unknown?null:percent(legacy?v.usage:v.current)??(used!==null&&total>0&&used<=total?Math.round(used/total*10000)/100:null)};}
function resource(r,kind,modern){
 const p=r.proxmox||{};const rawStatus=text(r.status)?.toLowerCase()||'unknown',verdict=['ok','attention','critical','stale','off','unknown'].includes(r.health?.verdict)?r.health.verdict:null;
 const status=verdict==='stale'?'Stale':verdict==='off'?'Stopped':verdict==='critical'?'Critical':verdict==='attention'?'Warning':['online','running','active'].includes(rawStatus)?'Connected':['offline','disconnected'].includes(rawStatus)?'Disconnected':['stopped','paused','suspended'].includes(rawStatus)?'Stopped':['warning','degraded'].includes(rawStatus)?'Warning':'Unknown';
 const cpu=modern?percent(r.cpu?.current):percent(number(r.cpu)!==null?(r.cpu<=1?r.cpu*100:r.cpu):null);
 return {id:text(r.id)||JSON.stringify([kind,text(r.instance),text(r.node),r.vmid,text(r.name)]),kind,name:text(r.displayName)||text(r.name)||text(r.node)||'Unnamed resource',
  node:text(modern?p.nodeName||r.parentName:r.node),instance:text(modern?p.instance||r.platformId:r.instance),vmid:Number.isSafeInteger(modern?p.vmid:r.vmid)?(modern?p.vmid:r.vmid):null,
  status,reportedStatus:rawStatus,verdict,cpuPercent:cpu,memory:usage(r.memory,!modern),disk:usage(kind==='storage'&&!modern?{used:r.used,total:r.total,usage:r.usage}:r.disk,!modern),
  uptime:number(r.uptime),lastSeen:time(r.lastSeen),version:text(r.pveVersion)||text(p.pveVersion)||text(p.version)};
}
export function sanitizePulse(state,now=Date.now()){
 if(!state||typeof state!=='object'||Array.isArray(state))throw new PulseError('Pulse returned an invalid state object.');
 let resources=[];let format;
 if(Array.isArray(state.resources)){
  format='unified';if(state.resources.length>10000)throw new PulseError('Pulse returned too many resources.');
  for(const r of state.resources){if(!r||typeof r!=='object')throw new PulseError('Pulse resource response is incomplete.');const pve=['proxmox','proxmox-pve','pve'].includes(r.platformType)||r.sourceType==='proxmox'||r.sources?.includes('proxmox');if(!pve||['proxmox-pbs','proxmox-pmg','pbs','pmg'].includes(r.platformType))continue;
   const kind={agent:'node',host:'node',node:'node',vm:'vm','system-container':'container',storage:'storage'}[r.type];if(kind)resources.push(resource(r,kind,true));}
 }else{
  format='legacy';if(!['nodes','vms','containers','storage'].every(k=>Array.isArray(state[k])))throw new PulseError('Pulse state response is incomplete. Expected PVE resources or node/VM/container/storage arrays.');
  for(const [key,kind] of [['nodes','node'],['vms','vm'],['containers','container'],['storage','storage']]){if(state[key].length>2000)throw new PulseError('Pulse returned too many PVE resources.');for(const r of state[key]){if(!r||typeof r!=='object')throw new PulseError('Pulse resource response is incomplete.');resources.push(resource(r,kind,false));}}
 }
 if(resources.length>2000)throw new PulseError('Pulse returned more than 2000 PVE resources; split this monitoring scope.');
 if(state.activeAlerts!==undefined&&!Array.isArray(state.activeAlerts))throw new PulseError('Pulse active-alert response is invalid.');
 const alerts=(state.activeAlerts||[]).slice(0,200).map(a=>({id:text(a?.id),resourceName:text(a?.resourceName),type:text(a?.type),level:['critical','warning','info'].includes(a?.level)?a.level:'warning',acknowledged:a?.acknowledged===true,startedAt:time(a?.startTime)}));
 const sourceUpdatedAt=time(state.lastUpdate),sourceStale=!sourceUpdatedAt||now-Date.parse(sourceUpdatedAt)>120000||Date.parse(sourceUpdatedAt)>now+60000;
 return {format,sourceUpdatedAt,sourceStale,resources,alerts,summary:{nodes:resources.filter(r=>r.kind==='node').length,vms:resources.filter(r=>r.kind==='vm').length,containers:resources.filter(r=>r.kind==='container').length,storage:resources.filter(r=>r.kind==='storage').length,activeAlerts:Array.isArray(state.activeAlerts)?state.activeAlerts.length:null,alertsTruncated:(state.activeAlerts?.length||0)>200}};
}
export class PulseSession {
 constructor(base,secret,options={}){this.base=pulseBase(base);this.secret=secret;this.fetch=options.fetcher||fetch;this.signal=options.signal;this.proxy=!!options.proxy;}
 async read(path){
  if(path!=='/state')throw new PulseError('Read endpoint not allowed.');let response;
  try{response=await this.fetch(this.base+path,{method:'GET',headers:{Accept:'application/json',Authorization:'Bearer '+cleanSecret(this.secret.key),...proxyHeaders(this.secret,this.proxy)},redirect:'manual',signal:this.signal?AbortSignal.any([this.signal,AbortSignal.timeout(10000)]):AbortSignal.timeout(10000)});}
  catch(e){const code=e?.cause?.code||e?.code;throw new PulseError(/CERT|SELF_SIGNED|UNABLE_TO_VERIFY|UNABLE_TO_GET_ISSUER/.test(code||'')?'Pulse TLS certificate is untrusted, expired or does not match the hostname.':['ENOTFOUND','EAI_AGAIN'].includes(code)?'Pulse hostname could not be resolved by the backend.':['AbortError','TimeoutError'].includes(e?.name)||['ETIMEDOUT','UND_ERR_CONNECT_TIMEOUT'].includes(code)?'Pulse request timed out. Check backend routing and the Pulse web port.':'Pulse connection failed. Check endpoint, TLS and backend reachability.');}
  if(response.status!==200){await response.body?.cancel();throw new PulseError(response.status===401?'Pulse authentication failed. Check the saved Pulse API token.':response.status===403?'Pulse denied access. Grant monitoring:read to the token and check reverse-proxy access.':response.status>=300&&response.status<400?'Pulse redirected to a login or proxy page. Use the direct API base URL.':response.status===404?'Pulse state API not found. Use the Pulse server base URL.':'Pulse returned HTTP '+response.status+'.');}
  try{return await smallJson(response,8*1024*1024);}catch{throw new PulseError('Pulse returned invalid or oversized JSON. Use its API endpoint.');}
 }
 async collect(){return sanitizePulse(await this.read('/state'));}
}

export async function pollPulse(env,record,{force=false,test=false,fetcher=fetch,now=Date.now()}={}){
 const db=env.DB,owner=record.owner,id=record.id,revision=record.revision;await db.prepare("INSERT INTO classic_cache (id,owner,revision) SELECT id,owner,revision FROM integrations WHERE id=? AND owner=? AND revision=? AND connector='pulse' ON CONFLICT(id) DO NOTHING").bind(id,owner,revision).run();const lease=crypto.randomUUID();const claimed=await db.prepare('UPDATE classic_cache SET lease=?,lease_until=?,last_attempt=? WHERE id=? AND owner=? AND revision=? AND lease_until<=? AND (next_due<=? OR ?=1)').bind(lease,now+90000,new Date(now).toISOString(),id,owner,revision,now,now,force?1:0).run();if(!claimed.meta.changes){let row=await db.prepare('SELECT * FROM classic_cache WHERE id=? AND owner=?').bind(id,owner).first();return {...classicView(row),skipped:true,status:row?.lease_until>now?'Poll already in progress':'Cached · next poll not due'}}
 let snapshot,error=null;const start=Date.now();try{pulseBase(record.endpoint);let secret=await decrypt(record.encrypted,env.INTEGRATION_ENCRYPTION_KEY,owner+':'+id);const session=new PulseSession(record.endpoint,secret,{fetcher,signal:AbortSignal.timeout(50000),proxy:!!record.proxy_auth});snapshot=await session.collect();if(JSON.stringify(snapshot).length>750000)throw new PulseError('Whitelisted snapshot exceeds the storage limit.')}catch(e){error=e instanceof PulseError?e.message:e instanceof ApiError?'Endpoint DNS validation failed.':'Pulse integration request failed.'}
 const finished=new Date().toISOString();
 // The configuration revision and lease fence late writes after edits or deletion.
 const valid="id=? AND owner=? AND revision=? AND lease=? AND EXISTS (SELECT 1 FROM integrations WHERE integrations.id=classic_cache.id AND integrations.revision=classic_cache.revision AND integrations.connector='pulse')";
 let written; if(!error&&snapshot)written=await db.prepare('UPDATE classic_cache SET session=?,snapshot=?,last_success=?,error=NULL,next_due=?,lease=NULL,lease_until=0 WHERE '+valid).bind(null,JSON.stringify(snapshot),finished,now+60000,id,owner,revision,lease).run();else written=await db.prepare('UPDATE classic_cache SET session=?,error=?,next_due=?,lease=NULL,lease_until=0 WHERE '+valid).bind(null,error,now+60000,id,owner,revision,lease).run();
 if(!written.meta.changes)return {...classicView(null),skipped:true,status:'Configuration changed; poll discarded'};
 await db.prepare("UPDATE integrations SET status=?,latency=?,checked_at=? WHERE id=? AND owner=? AND revision=?").bind(error?'Pulse polling failed':'Connected',Date.now()-start,finished,id,owner,revision).run();let row=await db.prepare('SELECT * FROM classic_cache WHERE id=? AND owner=?').bind(id,owner).first();return {...classicView(row),skipped:false,status:error?'Pulse polling failed':'Connected',latency:Date.now()-start}
}
