import {ApiError,endpoint,decrypt,authHeaders,proxyHeaders,smallJson} from './security.js';
import {classicView} from './unifi-classic.js';

export class AdGuardError extends Error {}
const count=value=>Number.isSafeInteger(value)&&value>=0?value:null;
const port=value=>count(value)!==null&&value>0&&value<=65535?value:null;
const number=value=>typeof value==='number'&&Number.isFinite(value)&&value>=0?value:null;
export function adguardBase(base) {
  const url=new URL(endpoint(base));
  if(!['/','/control','/control/'].includes(url.pathname))throw new ApiError('Use the AdGuard Home web URL, optionally ending in /control.');
  return url.origin+'/control';
}

export class AdGuardSession {
  constructor(base,secret,options={}) {
    this.base=adguardBase(base);this.secret=secret;this.fetch=options.fetcher||fetch;this.signal=options.signal;this.proxy=!!options.proxy;
  }
  async read(path) {
    if(!['/status','/stats'].includes(path))throw new AdGuardError('Read endpoint not allowed.');
    let response;
    try {
      response=await this.fetch(this.base+path,{method:'GET',headers:{...authHeaders('basic',null,this.secret),...proxyHeaders(this.secret,this.proxy)},redirect:'manual',
        signal:this.signal?AbortSignal.any([this.signal,AbortSignal.timeout(10000)]):AbortSignal.timeout(10000)});
    } catch(error) {
      const code=error?.cause?.code||error?.code;
      throw new AdGuardError(['CERT_HAS_EXPIRED','DEPTH_ZERO_SELF_SIGNED_CERT','SELF_SIGNED_CERT_IN_CHAIN','UNABLE_TO_VERIFY_LEAF_SIGNATURE','UNABLE_TO_GET_ISSUER_CERT_LOCALLY','ERR_TLS_CERT_ALTNAME_INVALID'].includes(code)?'AdGuard Home TLS certificate is untrusted, expired or does not match the hostname.':
        ['ENOTFOUND','EAI_AGAIN'].includes(code)?'AdGuard Home hostname could not be resolved by the backend.':
        code==='ECONNREFUSED'?'AdGuard Home refused the connection. Use its web interface port, not DNS port 53.':
        ['TimeoutError','AbortError'].includes(error?.name)||['ETIMEDOUT','UND_ERR_CONNECT_TIMEOUT'].includes(code)?'AdGuard Home request timed out. Check backend routing, firewall and the web service port.':'AdGuard Home connection failed. Check the web endpoint, TLS and backend reachability.');
    }
    if(response.status!==200) {
      await response.body?.cancel();
      const status=response.status;
      throw new AdGuardError(status>=300&&status<400?'AdGuard Home redirected to a login or proxy page. Use the direct web API URL.':
        status===401?'AdGuard Home authentication failed. Check the saved web-interface username and password.':
        status===403?'AdGuard Home denied access. Check the account and reverse-proxy access settings.':
        status===404?'AdGuard Home API route not found. Use its web interface base URL.':'AdGuard Home returned HTTP '+status+'.');
    }
    let data;
    try {data=await smallJson(response,2*1024*1024);}catch{throw new AdGuardError('AdGuard Home returned invalid or oversized JSON. Use the web API endpoint.');}
    if(!data||typeof data!=='object'||Array.isArray(data))throw new AdGuardError('AdGuard Home returned an invalid response object.');
    return data;
  }
  async collect() {
    const status=await this.read('/status'),stats=await this.read('/stats');
    if(typeof status.version!=='string'||!status.version||typeof status.protection_enabled!=='boolean')throw new AdGuardError('AdGuard Home status response is incomplete.');
    if(count(stats.num_dns_queries)===null||count(stats.num_blocked_filtering)===null)throw new AdGuardError('AdGuard Home statistics response is incomplete.');
    const started=number(status.start_time),average=number(stats.avg_processing_time),milliseconds=average!==null?average*1000:null;
    return {
      server:{version:status.version.slice(0,200),running:typeof status.running==='boolean'?status.running:null,protectionEnabled:status.protection_enabled,
        protectionDisabledDuration:count(status.protection_disabled_duration),dnsPort:port(status.dns_port),httpPort:port(status.http_port),
        startedAt:started!==null&&started>0&&started<=Date.now()?new Date(started).toISOString():null},
      stats:{queries:count(stats.num_dns_queries),blockedByFiltering:count(stats.num_blocked_filtering),
        blockedBySafeBrowsing:count(stats.num_replaced_safebrowsing),blockedByParental:count(stats.num_replaced_parental),safeSearchReplacements:count(stats.num_replaced_safesearch),
        averageProcessingMs:Number.isFinite(milliseconds)?Number(milliseconds.toFixed(2)):null,
        filteringPercent:stats.num_dns_queries>0&&stats.num_blocked_filtering<=stats.num_dns_queries?Math.round(stats.num_blocked_filtering/stats.num_dns_queries*10000)/100:stats.num_dns_queries===0&&stats.num_blocked_filtering===0?0:null}
    };
  }
}

export async function pollAdGuard(env,record,{force=false,test=false,fetcher=fetch,now=Date.now()}={}){
 const db=env.DB,owner=record.owner,id=record.id,revision=record.revision;await db.prepare("INSERT INTO classic_cache (id,owner,revision) SELECT id,owner,revision FROM integrations WHERE id=? AND owner=? AND revision=? AND connector='adguard' ON CONFLICT(id) DO NOTHING").bind(id,owner,revision).run();const lease=crypto.randomUUID();const claimed=await db.prepare('UPDATE classic_cache SET lease=?,lease_until=?,last_attempt=? WHERE id=? AND owner=? AND revision=? AND lease_until<=? AND (next_due<=? OR ?=1)').bind(lease,now+90000,new Date(now).toISOString(),id,owner,revision,now,now,force?1:0).run();if(!claimed.meta.changes){let row=await db.prepare('SELECT * FROM classic_cache WHERE id=? AND owner=?').bind(id,owner).first();return {...classicView(row),skipped:true,status:row?.lease_until>now?'Poll already in progress':'Cached · next poll not due'}}
 let snapshot,error=null;const start=Date.now();try{adguardBase(record.endpoint);let secret=await decrypt(record.encrypted,env.INTEGRATION_ENCRYPTION_KEY,owner+':'+id);const session=new AdGuardSession(record.endpoint,secret,{fetcher,signal:AbortSignal.timeout(50000),proxy:!!record.proxy_auth});snapshot=await session.collect();if(JSON.stringify(snapshot).length>750000)throw new AdGuardError('Whitelisted snapshot exceeds the storage limit.')}catch(e){error=e instanceof AdGuardError?e.message:e instanceof ApiError?'Endpoint DNS validation failed.':'AdGuard integration request failed.'}
 const finished=new Date().toISOString();
 // The configuration revision and lease fence late writes after edits or deletion.
 const valid="id=? AND owner=? AND revision=? AND lease=? AND EXISTS (SELECT 1 FROM integrations WHERE integrations.id=classic_cache.id AND integrations.revision=classic_cache.revision AND integrations.connector='adguard')";
 let written; if(!error&&snapshot)written=await db.prepare('UPDATE classic_cache SET session=?,snapshot=?,last_success=?,error=NULL,next_due=?,lease=NULL,lease_until=0 WHERE '+valid).bind(null,JSON.stringify(snapshot),finished,now+60000,id,owner,revision,lease).run();else written=await db.prepare('UPDATE classic_cache SET session=?,error=?,next_due=?,lease=NULL,lease_until=0 WHERE '+valid).bind(null,error,now+60000,id,owner,revision,lease).run();
 if(!written.meta.changes)return {...classicView(null),skipped:true,status:'Configuration changed; poll discarded'};
 await db.prepare("UPDATE integrations SET status=?,latency=?,checked_at=? WHERE id=? AND owner=? AND revision=?").bind(error?'AdGuard polling failed':'Connected',Date.now()-start,finished,id,owner,revision).run();let row=await db.prepare('SELECT * FROM classic_cache WHERE id=? AND owner=?').bind(id,owner).first();return {...classicView(row),skipped:false,status:error?'AdGuard polling failed':'Connected',latency:Date.now()-start}
}
