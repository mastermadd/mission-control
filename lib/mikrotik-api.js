import net from 'node:net';
import tls from 'node:tls';
import {lookup} from 'node:dns/promises';
import {ApiError,endpoint,cleanSecret} from './security.js';
import {MikroTikError,sanitizeMikroTik,pollMikroTik} from './mikrotik.js';

export function nativeEndpoint(value) {
  let url;
  try {url=new URL(value);} catch {throw new ApiError('Use tcp://router:8728 or tls://router:8729 for native MikroTik API.');}
  if (!['tcp:','tls:'].includes(url.protocol) || url.username || url.password || url.search || url.hash || !['','/'].includes(url.pathname)) throw new ApiError('Use tcp://router:8728 or tls://router:8729 without credentials or API paths.');
  const port=url.port?Number(url.port):url.protocol==='tls:'?8729:8728;
  if (!Number.isInteger(port) || port<1 || port>65535) throw new ApiError('Enter an API port between 1 and 65535.');
  // Preserve the internal edition's loopback and metadata protections.
  endpoint('http://'+url.host);
  return url.protocol+'//'+url.hostname+':'+port;
}

export function encodeSentence(words) {
  const parts=[];
  for (const word of words) {
    const body=Buffer.from(word,'utf8'),size=body.length;
    if(size>65536)throw new MikroTikError('MikroTik API word exceeds the size limit.');
    let prefix;
    if(size<0x80)prefix=Buffer.from([size]);
    else if(size<0x4000)prefix=Buffer.from([(size>>8)|0x80,size&255]);
    else prefix=Buffer.from([(size>>16)|0xc0,(size>>8)&255,size&255]);
    parts.push(prefix,body);
  }
  return Buffer.concat([...parts,Buffer.from([0])]);
}

export class SentenceDecoder {
  buffer=Buffer.alloc(0);words=[];size=0;
  push(chunk) {
    this.buffer=Buffer.concat([this.buffer,chunk]);
    if(this.buffer.length>2*1024*1024)throw new MikroTikError('MikroTik API response exceeds the size limit.');
    const sentences=[];
    while(this.buffer.length) {
      const first=this.buffer[0];
      let prefix=first<0x80?1:first<0xc0?2:first<0xe0?3:first<0xf0?4:first===0xf0?5:0;
      if(!prefix)throw new MikroTikError('MikroTik API returned an invalid length prefix.');
      if(this.buffer.length<prefix)break;
      let length=first&([0,255,0x3f,0x1f,0x0f,0][prefix]);
      for(let i=1;i<prefix;i++)length=length*256+this.buffer[i];
      if(length>65536)throw new MikroTikError('MikroTik API word exceeds the size limit.');
      if(this.buffer.length<prefix+length)break;
      if(length===0) {
        if(this.words.length)sentences.push(this.words);
        this.words=[];this.size=0;
      } else {
        this.size+=length;
        if(this.words.length>=128 || this.size>128*1024)throw new MikroTikError('MikroTik API sentence exceeds the size limit.');
        this.words.push(this.buffer.subarray(prefix,prefix+length).toString('utf8'));
      }
      this.buffer=this.buffer.subarray(prefix+length);
    }
    return sentences;
  }
}

const properties={
  '/system/identity/print':'name',
  '/system/resource/print':'board-name,version,uptime,architecture-name,cpu-load,total-memory,free-memory',
  '/interface/print':'name,type,running,disabled,actual-mtu,rx-byte,tx-byte'
};
function socketError(error) {
  const code=error?.code;
  if(['CERT_HAS_EXPIRED','DEPTH_ZERO_SELF_SIGNED_CERT','SELF_SIGNED_CERT_IN_CHAIN','UNABLE_TO_VERIFY_LEAF_SIGNATURE','UNABLE_TO_GET_ISSUER_CERT_LOCALLY','ERR_TLS_CERT_ALTNAME_INVALID'].includes(code))return new MikroTikError('MikroTik API-SSL certificate is untrusted, expired or does not match the hostname.');
  if(['ENOTFOUND','EAI_AGAIN'].includes(code))return new MikroTikError('MikroTik API hostname could not be resolved by the backend.');
  if(code==='ECONNREFUSED')return new MikroTikError('MikroTik API refused the connection. Enable api/api-ssl and check the port.');
  return new MikroTikError('MikroTik API connection failed. Check routing, firewall, service access restrictions and TLS settings.');
}
function blockedAddress(address) {
  const host=address.toLowerCase();
  if(host==='::' || host==='::1' || /^::ffff:(127\.|169\.254\.|0\.)/.test(host) || /^::ffff:(7f[0-9a-f]{2}:|a9fe:|0:)/.test(host))return true;
  if(!net.isIP(address))return true;
  try {endpoint('http://'+(host.includes(':')?'['+host+']':host));return host.startsWith('0.') || host.startsWith('fe80:');} catch {return true;}
}

export class NativeMikroTikSession {
  constructor(base,secret,options={}) {
    this.url=new URL(nativeEndpoint(base));this.secret=secret;this.options=options;
    this.signal=options.signal||AbortSignal.timeout(50000);this.socket=null;this.pending=null;this.failure=null;
  }
  fail(error) {
    this.failure=error;
    if(this.pending){const pending=this.pending;this.pending=null;clearTimeout(pending.timer);pending.reject(error);}
    this.socket?.destroy();
  }
  async connect() {
    const host=this.url.hostname.replace(/^\[|\]$/g,'');
    this.signal.throwIfAborted();
    let abort;
    const aborted=new Promise((_,reject)=>{
      abort=()=>reject(new MikroTikError('MikroTik API poll timed out.'));
      this.signal.addEventListener('abort',abort,{once:true});
    });
    let addresses;
    try {addresses=await Promise.race([net.isIP(host)?[{address:host}]:(this.options.lookup||lookup)(host,{all:true}),aborted]);}
    catch(error){throw error instanceof MikroTikError?error:socketError(error);}
    finally {this.signal.removeEventListener('abort',abort);}
    this.signal.throwIfAborted();
    if(!addresses.length || addresses.some(a=>blockedAddress(a.address)))throw new MikroTikError('MikroTik API endpoint resolves to a blocked loopback or metadata address.');
    const encrypted=this.url.protocol==='tls:';
    const options={host:addresses[0].address,port:Number(this.url.port),...(encrypted?{rejectUnauthorized:true,...(!net.isIP(host)?{servername:host}:{}),checkServerIdentity:(_name,cert)=>tls.checkServerIdentity(host,cert),...(this.options.ca?{ca:this.options.ca}:{})}:{})};
    const socket=this.socket=this.options.connect?this.options.connect(options,encrypted):encrypted?tls.connect(options):net.createConnection(options);
    this.onAbort=()=>this.fail(new MikroTikError('MikroTik API poll timed out.'));
    this.signal.addEventListener('abort',this.onAbort,{once:true});
    socket.on('error',error=>this.fail(socketError(error)));
    socket.on('close',()=>{if(!this.closed)this.fail(new MikroTikError('MikroTik API closed the connection before the request completed.'));});
    socket.setTimeout(this.options.timeoutMs||10000,()=>this.fail(new MikroTikError('MikroTik API request timed out. Check routing, firewall and service access restrictions.')));
    const decoder=new SentenceDecoder();
    socket.on('data',chunk=>{try{for(const words of decoder.push(chunk))this.receive(words);}catch(error){this.fail(error instanceof MikroTikError?error:new MikroTikError('MikroTik API returned an invalid response.'));}});
    await new Promise((resolve,reject)=>{
      const event=encrypted?'secureConnect':'connect';
      const timer=setTimeout(()=>this.fail(new MikroTikError('MikroTik API connection timed out. Check routing, firewall and service access restrictions.')),this.options.timeoutMs||10000);
      const failed=error=>{cleanup();reject(socketError(error));};
      const closed=()=>{cleanup();reject(this.failure||new MikroTikError('MikroTik API connection closed.'));};
      const ready=()=>{cleanup();resolve();};
      function cleanup(){clearTimeout(timer);socket.off('error',failed);socket.off('close',closed);socket.off(event,ready);}
      socket.once('error',failed);socket.once('close',closed);socket.once(event,ready);
    });
  }
  receive(words) {
    const type=words[0],pending=this.pending;
    if(type==='!fatal'){this.fail(new MikroTikError('MikroTik API terminated the session. Check the account and API service.'));return;}
    if(!pending){this.fail(new MikroTikError('MikroTik API returned an unexpected response.'));return;}
    pending.bytes+=words.reduce((sum,word)=>sum+Buffer.byteLength(word),0);
    if(pending.bytes>2*1024*1024){this.fail(new MikroTikError('MikroTik API response exceeds the size limit.'));return;}
    if(type==='!trap') {
      // Router error messages may echo submitted credentials; never return them.
      this.fail(new MikroTikError(pending.login?'MikroTik API login failed. Check the username, password and api account policy.':'MikroTik API read denied or failed. Check read and api account policies.'));
    } else if(type==='!re') {
      if(pending.login || pending.records.length>=2000){this.fail(new MikroTikError('MikroTik API returned an invalid record list.'));return;}
      const record=Object.create(null);
      for(const word of words.slice(1))if(word.startsWith('=')){const split=word.indexOf('=',1);if(split>1)record[word.slice(1,split)]=word.slice(split+1);}
      pending.records.push(record);
    } else if(type==='!done') {
      if(words.some(word=>word.startsWith('=ret='))){this.fail(new MikroTikError('Legacy MikroTik challenge login is not supported. Use RouterOS 6.43 or later.'));return;}
      this.pending=null;clearTimeout(pending.timer);pending.resolve(pending.records);
    } else if(type!=='!empty')this.fail(new MikroTikError('MikroTik API returned an unknown response type.'));
  }
  async request(command) {
    if(command!=='/login' && !Object.hasOwn(properties,command))throw new MikroTikError('Read command not allowed.');
    if(this.failure)throw this.failure;
    if(this.pending || !this.socket || this.socket.destroyed)throw new MikroTikError('MikroTik API session is unavailable or busy.');
    const login=command==='/login';
    const words=login?[command,'=name='+cleanSecret(this.secret.username),'=password='+cleanSecret(this.secret.password)]:[command,'=.proplist='+properties[command]];
    return new Promise((resolve,reject)=>{
      const timer=setTimeout(()=>this.fail(new MikroTikError('MikroTik API command timed out.')),this.options.timeoutMs||10000);
      this.pending={resolve,reject,timer,records:[],bytes:0,login};
      try{this.socket.write(encodeSentence(words));}catch{this.fail(new MikroTikError('MikroTik API could not send the request.'));}
    });
  }
  close() {
    this.closed=true;
    if(this.pending)this.fail(new MikroTikError('MikroTik API session closed.'));
    this.signal.removeEventListener('abort',this.onAbort);
    this.socket?.destroy();
  }
  async collect() {
    try {
      await this.connect();await this.request('/login');
      const identity=await this.request('/system/identity/print');
      const resources=await this.request('/system/resource/print');
      const interfaces=await this.request('/interface/print');
      return sanitizeMikroTik(identity,resources,interfaces);
    } finally {this.close();}
  }
}

export function pollMikroTikAPI(env,record,options={}) {
  return pollMikroTik(env,record,{...options,sessionFactory:(base,secret,opts)=>new NativeMikroTikSession(base,secret,{...opts,...options})});
}
