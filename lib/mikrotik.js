import {ApiError,decrypt} from './security.js';
import {classicView} from './unifi-classic.js';

export class MikroTikError extends Error {}
const text = value => typeof value === 'string' ? value.slice(0,256) : null;
const number = value => (typeof value === 'number' || typeof value === 'string' && /^\d+(\.\d+)?$/.test(value)) && Number.isFinite(Number(value)) && Number(value) >= 0 ? Number(value) : null;
const flag = value => value === true || value === 'true' || value === 'yes' ? true : value === false || value === 'false' || value === 'no' ? false : null;

export function sanitizeMikroTik(identity,resources,interfaces) {
    if (identity.length !== 1 || resources.length !== 1 || !text(identity[0].name) || !text(resources[0].version)) throw new MikroTikError('MikroTik identity or system resource response is incomplete.');
    const resource = resources[0], totalMemory = number(resource['total-memory']), freeMemory = number(resource['free-memory']);
    return {
      router:{name:text(identity[0].name),model:text(resource['board-name']),version:text(resource.version),uptime:text(resource.uptime),
        architecture:text(resource['architecture-name']),cpuLoad:number(resource['cpu-load']),totalMemory,freeMemory,
        memoryUsage:totalMemory > 0 && freeMemory !== null && freeMemory <= totalMemory ? Math.round((totalMemory-freeMemory)/totalMemory*100) : null},
      interfaces:interfaces.map(item => ({name:text(item.name),type:text(item.type),running:flag(item.running),disabled:flag(item.disabled),
        mtu:number(item['actual-mtu']),rxBytes:number(item['rx-byte']),txBytes:number(item['tx-byte'])}))
    };
}

export async function pollMikroTik(env,record,{force=false,test=false,fetcher=fetch,now=Date.now(),sessionFactory}={}){
 if(record.connector!=='mikrotik-api'||typeof sessionFactory!=='function')throw new ApiError('Unknown MikroTik connector.');
 const db=env.DB,owner=record.owner,id=record.id,revision=record.revision;await db.prepare("INSERT INTO classic_cache (id,owner,revision) SELECT id,owner,revision FROM integrations WHERE id=? AND owner=? AND revision=? AND connector=? ON CONFLICT(id) DO NOTHING").bind(id,owner,revision,record.connector).run();const lease=crypto.randomUUID();const claimed=await db.prepare('UPDATE classic_cache SET lease=?,lease_until=?,last_attempt=? WHERE id=? AND owner=? AND revision=? AND lease_until<=? AND (next_due<=? OR ?=1)').bind(lease,now+90000,new Date(now).toISOString(),id,owner,revision,now,now,force?1:0).run();if(!claimed.meta.changes){let row=await db.prepare('SELECT * FROM classic_cache WHERE id=? AND owner=?').bind(id,owner).first();return {...classicView(row),skipped:true,status:row?.lease_until>now?'Poll already in progress':'Cached · next poll not due'}}
 let snapshot,error=null;const start=Date.now();try{let secret=await decrypt(record.encrypted,env.INTEGRATION_ENCRYPTION_KEY,owner+':'+id);const session=sessionFactory(record.endpoint,secret,{fetcher,signal:AbortSignal.timeout(50000),proxy:!!record.proxy_auth});snapshot=await session.collect();if(JSON.stringify(snapshot).length>750000)throw new MikroTikError('Whitelisted snapshot exceeds the storage limit.')}catch(e){error=e instanceof MikroTikError?e.message:e instanceof ApiError?'Endpoint DNS validation failed.':'MikroTik integration request failed.'}
 const finished=new Date().toISOString();
 // The configuration revision and lease fence late writes after edits or deletion.
 const valid="id=? AND owner=? AND revision=? AND lease=? AND EXISTS (SELECT 1 FROM integrations WHERE integrations.id=classic_cache.id AND integrations.revision=classic_cache.revision AND integrations.connector=?)";
 let written; if(!error&&snapshot)written=await db.prepare('UPDATE classic_cache SET session=?,snapshot=?,last_success=?,error=NULL,next_due=?,lease=NULL,lease_until=0 WHERE '+valid).bind(null,JSON.stringify(snapshot),finished,now+60000,id,owner,revision,lease,record.connector).run();else written=await db.prepare('UPDATE classic_cache SET session=?,error=?,next_due=?,lease=NULL,lease_until=0 WHERE '+valid).bind(null,error,now+60000,id,owner,revision,lease,record.connector).run();
 if(!written.meta.changes)return {...classicView(null),skipped:true,status:'Configuration changed; poll discarded'};
 await db.prepare("UPDATE integrations SET status=?,latency=?,checked_at=? WHERE id=? AND owner=? AND revision=?").bind(error?'MikroTik polling failed':'Connected',Date.now()-start,finished,id,owner,revision).run();let row=await db.prepare('SELECT * FROM classic_cache WHERE id=? AND owner=?').bind(id,owner).first();return {...classicView(row),skipped:false,status:error?'MikroTik polling failed':'Connected',latency:Date.now()-start}
}
