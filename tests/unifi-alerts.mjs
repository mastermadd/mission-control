import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

test('UniFi alerts only on fresh confirmed adopted device disconnections, ignoring subsystem health and stale controllers',()=>{
 const source=fs.readFileSync(new URL('../public/app.js',import.meta.url),'utf8');
 const functions=['operationAlerts','telemetryConnector','cacheStale'].map(name=>source.split('\n').find(line=>line.startsWith('function '+name+'('))).join('\n');
 const health=['wan','lan','wlan','vpn','www'].map(subsystem=>({subsystem,status:'unknown'}));
 const snapshot={lastSuccess:new Date().toISOString(),stale:false,data:{sites:[{name:'default',desc:'School',health,devices:[
  {name:'Offline switch',adopted:true,state:0}, {name:'Online AP',adopted:true,state:1},
  {name:'Discovered',adopted:false,state:0}, {name:'Pending',adopted:true,state:2}, {name:'Unknown',adopted:null,state:0}
 ]}]}};
 const saved={id:1,title:'Existing saved alert'};
 const context=vm.createContext({Date,vault:[{id:'unifi',connector:'unifi-classic',name:'Controller',customer:'School'}],classicData:{unifi:snapshot},state:{alerts:[saved]}});
 vm.runInContext(functions,context);
 let alerts=vm.runInContext('operationAlerts()',context);assert.equal(alerts.length,2);assert.equal(alerts[0].title,'Offline switch · disconnected');assert.equal(alerts[0].source,'School · School');assert.equal(alerts[1],saved);
 for(const h of health)h.status='error';assert.equal(vm.runInContext('operationAlerts().length',context),2);
 snapshot.data.sites[0].devices[0].state=1;assert.equal(vm.runInContext('operationAlerts().length',context),1);
 snapshot.data.sites[0].devices[0].state=0;snapshot.stale=true;snapshot.error='Controller unreachable';assert.equal(vm.runInContext('operationAlerts().length',context),1);
 snapshot.stale=false;snapshot.lastSuccess=new Date(Date.now()-180000).toISOString();assert.equal(vm.runInContext('operationAlerts().length',context),1);
 delete context.classicData.unifi;assert.equal(vm.runInContext('operationAlerts().length',context),1);
 // Stale monitoring for other connectors still raises their existing integration alert.
 context.vault=[{id:'dns',connector:'adguard',name:'DNS'}];alerts=vm.runInContext('operationAlerts()',context);assert.equal(alerts.length,2);assert.match(alerts[0].title,/telemetry stale/);
});
