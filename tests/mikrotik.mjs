import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

test('MikroTik frontend joins customer inventory, network views and stale telemetry alerts', () => {
  const source=fs.readFileSync(new URL('../public/app.js',import.meta.url),'utf8');
  const names=['telemetryConnector','mikrotikAssets','mikrotikPanel','classicPanel','classicSummary','cacheStale','integrationAssets','operationAlerts','customerIntegrations'];
  const functions=names.map(name=>source.split('\n').find(line=>line.startsWith('function '+name+'('))).join('\n');
  const integration={id:'router',name:'Router API',connector:'mikrotik-api',customer:'School',endpoint:'https://router.internal',status:'Connected'};
  const snapshot={lastSuccess:new Date().toISOString(),stale:false,data:{router:{name:'<Router>',model:'RB4011',version:'7.15.1',uptime:'1w2d',cpuLoad:15,memoryUsage:75},interfaces:[{name:'ether1',running:true,disabled:false,rxBytes:12345,txBytes:67890}]}};
  const context=vm.createContext({vault:[integration],classicData:{router:snapshot},state:{alerts:[]},esc:value=>String(value??'').replaceAll('<','&lt;'),panel:(title,html)=>title+html,tag:value=>value,Date});
  vm.runInContext(functions,context);
  const assets=vm.runInContext('integrationAssets()',context);
  assert.equal(assets[0].customer,'School');
  assert.equal(assets[0].integrationId,'router');
  assert.equal(assets[0].live,true);
  assert.equal(assets[0].status,'Connected');
  const html=vm.runInContext("classicPanel('router')",context);
  assert(html.includes('MikroTik data'));
  assert(html.includes('&lt;Router>'));
  assert(html.includes('12345'));
  assert(vm.runInContext("customerIntegrations('School')",context).includes('Router API'));
  snapshot.stale=true;snapshot.error='Request timed out';
  assert.equal(vm.runInContext('integrationAssets()[0].status',context),'Connected');
  assert.equal(vm.runInContext('integrationAssets()[0].stale',context),true);
  assert.equal(vm.runInContext('operationAlerts()[0].title',context),'Router API · telemetry stale');
  context.vault=[];
  assert.equal(vm.runInContext('integrationAssets().length',context),0);
});

