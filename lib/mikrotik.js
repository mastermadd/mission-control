import {ApiError,endpoint,decrypt,authHeaders,proxyHeaders,smallJson} from './security.js';
import {classicView} from './unifi-classic.js';

export class MikroTikError extends Error {}
const text = value => typeof value === 'string' ? value.slice(0,256) : null;
const number = value => (typeof value === 'number' || typeof value === 'string' && /^\d+(\.\d+)?$/.test(value)) && Number.isFinite(Number(value)) && Number(value) >= 0 ? Number(value) : null;
const flag = value => value === true || value === 'true' ? true : value === false || value === 'false' ? false : null;

export function mikrotikBase(base) {
  const url = new URL(endpoint(base));
  if (!['/','/rest','/rest/'].includes(url.pathname)) throw new ApiError('Use the MikroTik base URL, optionally ending in /rest.');
  if (['8728','8729'].includes(url.port)) throw new ApiError('MikroTik REST uses the www/www-ssl HTTP service, not API ports 8728/8729.');
  return url.origin + '/rest';
}

function connectionError(error) {
  const code = error?.cause?.code || error?.code;
  if (['CERT_HAS_EXPIRED','DEPTH_ZERO_SELF_SIGNED_CERT','SELF_SIGNED_CERT_IN_CHAIN','UNABLE_TO_VERIFY_LEAF_SIGNATURE','UNABLE_TO_GET_ISSUER_CERT_LOCALLY','ERR_TLS_CERT_ALTNAME_INVALID'].includes(code)) return 'MikroTik TLS certificate is untrusted, expired or does not match the hostname. Use a trusted certificate and matching hostname.';
  if (['ENOTFOUND','EAI_AGAIN'].includes(code)) return 'MikroTik hostname could not be resolved by the backend.';
  if (code === 'ECONNREFUSED') return 'MikroTik refused the connection. Check www/www-ssl and its port.';
  if (['TimeoutError','AbortError'].includes(error?.name) || ['ETIMEDOUT','UND_ERR_CONNECT_TIMEOUT'].includes(code)) return 'MikroTik request timed out. Check routing, firewall and service access restrictions from the dashboard server.';
  return 'MikroTik connection failed. Check the REST web service, port, TLS and backend reachability.';
}

export class MikroTikSession {
  constructor(base, secret, options = {}) {
    this.base = mikrotikBase(base);
    this.secret = secret;
    this.fetch = options.fetcher || fetch;
    this.signal = options.signal;
    this.proxy = !!options.proxy;
  }
  async read(path) {
    if (!['/system/identity','/system/resource','/interface'].includes(path)) throw new MikroTikError('Read endpoint not allowed.');
    let response;
    try {
      response = await this.fetch(this.base + path, {
        method:'GET', headers:{...authHeaders('basic',null,this.secret),...proxyHeaders(this.secret,this.proxy)},
        redirect:'manual', signal:this.signal ? AbortSignal.any([this.signal,AbortSignal.timeout(10000)]) : AbortSignal.timeout(10000)
      });
    } catch (error) {throw new MikroTikError(connectionError(error));}
    if (response.status !== 200) {
      await response.body?.cancel();
      const status = response.status;
      throw new MikroTikError(status >= 300 && status < 400 ? 'MikroTik returned a redirect. Use the REST service URL directly.' :
        status === 401 ? 'MikroTik authentication failed. Check the saved username and password.' :
        status === 403 ? 'MikroTik denied access. Check read and rest-api user policies, service access restrictions and proxy authentication.' :
        status === 404 ? 'MikroTik REST endpoint not found. Use RouterOS 7 with www/www-ssl enabled.' : 'MikroTik returned HTTP '+status+'.');
    }
    let records;
    try {records = await smallJson(response, 2*1024*1024);} catch {throw new MikroTikError('MikroTik returned invalid or oversized JSON. Use its REST endpoint, not the WebFig login page.');}
    if (!Array.isArray(records) || records.length > 2000 || records.some(record => !record || typeof record !== 'object' || Array.isArray(record))) throw new MikroTikError('MikroTik returned an invalid record list.');
    return records;
  }
  async collect() {
    const identity = await this.read('/system/identity');
    const resources = await this.read('/system/resource');
    const interfaces = await this.read('/interface');
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
}

export async function pollMikroTik(env,record,{force=false,test=false,fetcher=fetch,now=Date.now()}={}){
 const db=env.DB,owner=record.owner,id=record.id,revision=record.revision;await db.prepare("INSERT INTO classic_cache (id,owner,revision) SELECT id,owner,revision FROM integrations WHERE id=? AND owner=? AND revision=? AND connector='mikrotik' ON CONFLICT(id) DO NOTHING").bind(id,owner,revision).run();const lease=crypto.randomUUID();const claimed=await db.prepare('UPDATE classic_cache SET lease=?,lease_until=?,last_attempt=? WHERE id=? AND owner=? AND revision=? AND lease_until<=? AND (next_due<=? OR ?=1)').bind(lease,now+90000,new Date(now).toISOString(),id,owner,revision,now,now,force?1:0).run();if(!claimed.meta.changes){let row=await db.prepare('SELECT * FROM classic_cache WHERE id=? AND owner=?').bind(id,owner).first();return {...classicView(row),skipped:true,status:row?.lease_until>now?'Poll already in progress':'Cached · next poll not due'}}
 let snapshot,error=null;const start=Date.now();try{mikrotikBase(record.endpoint);let secret=await decrypt(record.encrypted,env.INTEGRATION_ENCRYPTION_KEY,owner+':'+id);const session=new MikroTikSession(record.endpoint,secret,{fetcher,signal:AbortSignal.timeout(50000),proxy:!!record.proxy_auth});snapshot=await session.collect();if(JSON.stringify(snapshot).length>750000)throw new MikroTikError('Whitelisted snapshot exceeds the storage limit.')}catch(e){error=e instanceof MikroTikError?e.message:e instanceof ApiError?'Endpoint DNS validation failed.':'MikroTik integration request failed.'}
 const finished=new Date().toISOString();
 // The configuration revision and lease fence late writes after edits or deletion.
 const valid="id=? AND owner=? AND revision=? AND lease=? AND EXISTS (SELECT 1 FROM integrations WHERE integrations.id=classic_cache.id AND integrations.revision=classic_cache.revision AND integrations.connector='mikrotik')";
 let written; if(!error&&snapshot)written=await db.prepare('UPDATE classic_cache SET session=?,snapshot=?,last_success=?,error=NULL,next_due=?,lease=NULL,lease_until=0 WHERE '+valid).bind(null,JSON.stringify(snapshot),finished,now+60000,id,owner,revision,lease).run();else written=await db.prepare('UPDATE classic_cache SET session=?,error=?,next_due=?,lease=NULL,lease_until=0 WHERE '+valid).bind(null,error,now+60000,id,owner,revision,lease).run();
 if(!written.meta.changes)return {...classicView(null),skipped:true,status:'Configuration changed; poll discarded'};
 await db.prepare("UPDATE integrations SET status=?,latency=?,checked_at=? WHERE id=? AND owner=? AND revision=?").bind(error?'MikroTik polling failed':'Connected',Date.now()-start,finished,id,owner,revision).run();let row=await db.prepare('SELECT * FROM classic_cache WHERE id=? AND owner=?').bind(id,owner).first();return {...classicView(row),skipped:false,status:error?'MikroTik polling failed':'Connected',latency:Date.now()-start}
}
