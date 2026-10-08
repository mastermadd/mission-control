import {test} from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import tls from 'node:tls';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import vm from 'node:vm';
import {NativeMikroTikSession,SentenceDecoder,encodeSentence,nativeEndpoint,pollMikroTikAPI} from '../lib/mikrotik-api.js';
import {LocalDB} from '../db.mjs';
import {encrypt} from '../lib/security.js';
import {passwordHash} from '../auth.mjs';
import {startServer} from '../server.mjs';

const secret={username:'fixture-reader',password:'FIXTURE-PASSWORD-ONLY'};
const records={
  '/system/identity/print':[{name:'Native Router',password:'DO-NOT-EXPOSE'}],
  '/system/resource/print':[{version:'7.15.1',uptime:'1d2h','board-name':'RB4011','cpu-load':'12','total-memory':'1024','free-memory':'256',secret:'DO-NOT-EXPOSE'}],
  '/interface/print':[{name:'ether1',running:'yes',disabled:'no','rx-byte':'12000','tx-byte':'3000','mac-address':'DO-NOT-EXPOSE'},{name:'ether2',running:'no',disabled:'yes'}]
};
import {cert,key} from './native-tls-fixture.js';
async function fixture({secure=false,deny=false,hang=false,close=false}={}) {
  const calls=[],sockets=new Set();
  const handler=socket=>{
    sockets.add(socket);socket.on('close',()=>sockets.delete(socket));socket.on('error',()=>{});
    const decoder=new SentenceDecoder();
    socket.on('data',chunk=>{
      for(const words of decoder.push(chunk)) {
        calls.push(words);
        if(hang)continue;
        if(close){socket.destroy();continue;}
        let reply;
        if(words[0]==='/login') {
          assert.equal(words[1],'=name='+secret.username);
          assert.equal(words[2],'=password='+secret.password);
          reply=deny?encodeSentence(['!trap','=message=bad '+secret.password]):encodeSentence(['!done']);
        } else {
          assert(Object.hasOwn(records,words[0]),'Only documented read commands are sent');
          assert(words[1].startsWith('=.proplist='));
          reply=Buffer.concat([...records[words[0]].map(record=>encodeSentence(['!re',...Object.entries(record).map(([name,value])=>'='+name+'='+value)])),encodeSentence(['!done'])]);
        }
        // Exercise incomplete words, sentence boundaries and multiple replies in one read.
        socket.write(reply.subarray(0,2));setImmediate(()=>{if(!socket.destroyed)socket.write(reply.subarray(2));});
      }
    });
  };
  const server=secure?tls.createServer({key,cert},handler):net.createServer(handler);
  server.on('tlsClientError',()=>{});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const port=server.address().port;
  return {port,calls,options:{lookup:async()=>[{address:'192.168.5.1'}],connect:(options,encrypted)=>encrypted?tls.connect({...options,host:'127.0.0.1',port}):net.createConnection({...options,host:'127.0.0.1',port})},
    async stop(){for(const socket of sockets)socket.destroy();await new Promise(resolve=>server.close(resolve));}};
}

test('Native API uses plain TCP login and bounded read commands, whitelisting RouterOS 7.15.1 data',async()=>{
  const router=await fixture();
  try {
    const session=new NativeMikroTikSession('tcp://router.test:8728',secret,router.options);
    const data=await session.collect();
    assert.deepEqual(router.calls.map(words=>words[0]),['/login','/system/identity/print','/system/resource/print','/interface/print']);
    assert.equal(data.router.name,'Native Router');assert.equal(data.router.cpuLoad,12);assert.equal(data.router.memoryUsage,75);
    assert.equal(data.interfaces[0].running,true);assert.equal(data.interfaces[0].disabled,false);assert.equal(data.interfaces[1].disabled,true);
    assert.equal(data.interfaces[0].rxBytes,12000);assert(!JSON.stringify(data).includes('DO-NOT-EXPOSE'));assert(!JSON.stringify(data).includes(secret.password));
    assert.equal(session.socket.destroyed,true);
    await assert.rejects(session.request('/system/reboot'),/Read command not allowed/);
  }finally{await router.stop();}
});

test('Native API-SSL checks certificates and supports a trusted private CA',async()=>{
  const router=await fixture({secure:true});
  try {
    await assert.rejects(new NativeMikroTikSession('tls://router.test:8729',secret,router.options).collect(),/certificate is untrusted/);
    const data=await new NativeMikroTikSession('tls://router.test:8729',secret,{...router.options,ca:cert}).collect();
    assert.equal(data.router.version,'7.15.1');
    await assert.rejects(new NativeMikroTikSession('tls://wrong.test:8729',secret,{...router.options,ca:cert}).collect(),/certificate is untrusted/);
  }finally{await router.stop();}
});

test('Native API rejects authentication, hanging reads, premature disconnects and protected destinations safely',async()=>{
  for(const [options,pattern] of [[{deny:true},/login failed/],[{hang:true},/timed out/],[{close:true},/closed the connection/]]) {
    const router=await fixture(options);
    try {await assert.rejects(new NativeMikroTikSession('tcp://router.test',secret,{...router.options,timeoutMs:50}).collect(),error=>pattern.test(error.message)&&!error.message.includes(secret.password));}
    finally{await router.stop();}
  }
  for(const address of ['127.0.0.1','169.254.169.254','::1','::ffff:127.0.0.1']) {
    await assert.rejects(new NativeMikroTikSession('tcp://router.test',secret,{lookup:async()=>[{address}],connect:()=>{throw Error('Must not connect');}}).collect(),/blocked loopback or metadata/);
  }
  assert.equal(nativeEndpoint('tcp://192.168.5.1'),'tcp://192.168.5.1:8728');
  assert.equal(nativeEndpoint('tls://router.internal'),'tls://router.internal:8729');
  assert.equal(nativeEndpoint('tcp://[fd00::5]:9000'),'tcp://[fd00::5]:9000');
  for(const url of ['tcp://localhost:8728','tcp://169.254.169.254:8728','tcp://127.0.0.1:8728','http://router.internal:8728','tcp://user:password@router.internal:8728','tcp://router.internal/rest'])assert.throws(()=>nativeEndpoint(url));
});

test('Native frame parsing handles UTF-8 and all length prefix forms with strict limits',()=>{
  assert.equal(encodeSentence(['a']).toString('hex'),'016100');
  assert.deepEqual([...encodeSentence(['a'.repeat(128)]).subarray(0,2)],[0x80,0x80]);
  assert.deepEqual([...encodeSentence(['a'.repeat(16384)]).subarray(0,3)],[0xc0,0x40,0]);
  const decoder=new SentenceDecoder(),frame=encodeSentence(['!re','=name=Róuter','='.repeat(200)]),out=[];
  for(const byte of frame)out.push(...decoder.push(Buffer.from([byte])));
  assert.deepEqual(out,[['!re','=name=Róuter','='.repeat(200)]]);
  assert.deepEqual(new SentenceDecoder().push(Buffer.from([0xe0,0,0,1,97,0])),[['a']]);
  assert.deepEqual(new SentenceDecoder().push(Buffer.from([0xf0,0,0,0,1,97,0])),[['a']]);
  assert.throws(()=>new SentenceDecoder().push(Buffer.from([0xff])),/invalid length/);
  assert.throws(()=>new SentenceDecoder().push(Buffer.from([0xe0,2,0,0])),/word exceeds/);
});

test('Native poll uses encrypted settings, caches snapshots and preserves last success after failed reads',async()=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'mission-native-')),db=new LocalDB(path.join(dir,'db.sqlite')),router=await fixture();
  const env={DB:db,INTEGRATION_ENCRYPTION_KEY:'de'.repeat(32)};
  try {
    const encrypted=await encrypt(secret,env.INTEGRATION_ENCRYPTION_KEY,'owner:router');
    await db.prepare('INSERT INTO integrations (id,owner,connector,name,endpoint,mode,auth,encrypted,status,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)').bind('router','owner','mikrotik-api','Native Router','tcp://router.test:8728','direct','basic',encrypted,'Not tested','now').run();
    const record=await db.prepare('SELECT * FROM integrations WHERE id=?').bind('router').first();
    const success=await pollMikroTikAPI(env,record,{...router.options,force:true});
    assert.equal(success.status,'Connected');assert.equal(success.data.router.name,'Native Router');
    const skipped=await pollMikroTikAPI(env,record,router.options);assert.equal(skipped.skipped,true);assert.equal(router.calls.length,4);
    const failed=await pollMikroTikAPI(env,record,{force:true,lookup:async()=>[{address:'127.0.0.1'}]});
    assert.equal(failed.stale,true);assert.deepEqual(failed.data,success.data);assert.equal(failed.lastSuccess,success.lastSuccess);
    assert(!JSON.stringify(failed).includes(secret.password));
  }finally{await router.stop();db.close();fs.rmSync(dir,{recursive:true,force:true});}
});

test('Native transport form switches defaults/custom ports and preserves customer selection',()=>{
  const source=fs.readFileSync(new URL('../public/app.js',import.meta.url),'utf8');
  const functions=['selectConnector','selectNativeTransport','integrationFields','telemetryConnector'].map(name=>source.split('\n').find(line=>line.startsWith('function '+name+'('))).join('\n');
  const nodes=new Map(),$=selector=>{if(!nodes.has(selector))nodes.set(selector,{value:'',style:{}});return nodes.get(selector);};
  $('#f-connector').value='mikrotik-api';$('#f-endpoint').value='https://router.internal/rest';$('#f-customer').value='School';$('#f-proxyAuth').value='pangolin';
  const context=vm.createContext({$,document:{querySelector:$},URL});vm.runInContext(functions+'\nselectConnector();',context);
  assert.equal($('#f-endpoint').value,'tcp://router.internal:8728');assert.equal($('#f-auth').value,'basic');assert.equal($('#f-customer').value,'School');
  assert.equal($('#f-proxyAuth').value,'none');assert.equal($('#native-fields').style.display,'block');
  $('#f-native-transport').value='tls';vm.runInContext('selectNativeTransport()',context);assert.equal($('#f-endpoint').value,'tls://router.internal:8729');
  $('#f-endpoint').value='tls://router.internal:9000';$('#f-native-transport').value='tcp';vm.runInContext('selectNativeTransport()',context);assert.equal($('#f-endpoint').value,'tcp://router.internal:9000');
  assert.equal(vm.runInContext("telemetryConnector({connector:'mikrotik-api'})",context),true);
});

test('Authenticated native API flow preserves saved credentials, polls automatically and removes linked caches',async()=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'mission-native-api-')),router=await fixture();
  const config={origin:'http://localhost:8080',username:'admin',password:passwordHash('fixture-admin-password'),encryptionKey:'ef'.repeat(32)};
  const app=startServer(config,{database:path.join(dir,'db.sqlite'),port:0,host:'127.0.0.1',poll:false});
  await new Promise(resolve=>app.server.once('listening',resolve));
  const originalConnect=net.createConnection;
  // Route this synthetic internal router address to the local fixture socket.
  net.createConnection=function(options,...args){return originalConnect.call(net,options.host==='192.168.5.250'?{...options,host:'127.0.0.1'}:options,...args);};
  const base='http://127.0.0.1:'+app.server.address().port;let cookie='';
  async function request(url,method='GET',data){const response=await fetch(base+url,{method,headers:{Origin:config.origin,'Content-Type':'application/json',Cookie:cookie},...(data===undefined?{}:{body:JSON.stringify(data)})});return {status:response.status,cookie:response.headers.get('set-cookie'),data:await response.json()};}
  try {
    const login=await request('/auth/login','POST',{username:'admin',password:'fixture-admin-password'});cookie=login.cookie.split(';')[0];
    await request('/api/customers','POST',{name:'School',type:'Education',contact:'IT'});
    const id='legacy-router',encrypted=await encrypt(secret,config.encryptionKey,'local-admin:'+id);
    await app.db.prepare('INSERT INTO integrations (id,owner,connector,name,endpoint,mode,auth,customer,encrypted,status,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)').bind(id,'local-admin','generic','Router','https://router.internal','direct','basic','School',encrypted,'Connected','now').run();
    const settings={name:'Router',connector:'mikrotik-api',endpoint:'tcp://192.168.5.250:'+router.port,mode:'direct',auth:'basic',customer:'School'};
    assert.equal((await request('/api/integrations/'+id,'PATCH',{...settings,proxyAuth:true})).status,400);
    assert.equal((await request('/api/integrations/'+id,'PATCH',settings)).status,200);
    const tested=await request('/api/integrations/'+id+'/test','POST',{});
    assert.equal(tested.data.status,'Connected');assert.equal(tested.data.data.router.name,'Native Router');assert.equal(router.calls.length,4);
    await app.pollAll();assert.equal(router.calls.length,4);
    const cached=await request('/api/integrations/'+id+'/data');assert.equal(cached.data.lastSuccess,tested.data.lastSuccess);
    assert(!JSON.stringify(cached.data).includes(secret.password));
    assert.equal((await request('/api/assets','DELETE',{integrationId:id})).status,403);
    assert.equal((await request('/api/customers/0','DELETE',{expectedName:'School'})).status,200);
    assert.equal((await request('/api/integrations')).data.integrations.length,0);
    assert.equal(await app.db.prepare('SELECT * FROM classic_cache WHERE id=?').bind(id).first(),null);
  }finally{net.createConnection=originalConnect;await app.close();await router.stop();fs.rmSync(dir,{recursive:true,force:true});}
});
