import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

test('Account dropdown supports dismissing, importing and secure logout with failure recovery', async () => {
  function element() {
    return {handlers: {}, hidden: true, attrs: {}, addEventListener(name, fn) {this.handlers[name] = fn;},
      setAttribute(name, value) {this.attrs[name] = value;}, focus() {this.focused = true;}};
  }
  const root = element(), toggle = element(), actions = element(), importer = element(), logout = element();
  const nodes = {'#user-menu':root, '#user-toggle':toggle, '#user-actions':actions, '#import-workspace':importer, '#sign-out':logout};
  root.contains = target => Object.values(nodes).includes(target);
  const document = element();
  document.querySelector = id => nodes[id];
  const location = {href:'/dashboard.html'}, requests = [], notices = [];
  let imports = 0, response = {ok:true, status:200};
  vm.runInNewContext(fs.readFileSync(new URL('../public/user-menu.js', import.meta.url), 'utf8'), {
    document, location, migrationDialog:() => imports++, toast:message => notices.push(message),
    fetch:async (url, options) => {requests.push({url, options});return response;}
  });
  toggle.handlers.click();
  assert.equal(actions.hidden, false);
  assert.equal(toggle.attrs['aria-expanded'], 'true');
  document.handlers.click({target:importer});
  assert.equal(actions.hidden, false);
  root.handlers.keydown({key:'Escape', preventDefault() {}});
  assert.equal(actions.hidden, true);
  assert.equal(toggle.focused, true);
  toggle.handlers.click();
  document.handlers.click({target:{}});
  assert.equal(actions.hidden, true);
  toggle.handlers.click();
  root.handlers.focusout({relatedTarget:logout});
  assert.equal(actions.hidden, false);
  root.handlers.focusout({relatedTarget:{}});
  assert.equal(actions.hidden, true);
  toggle.handlers.click();
  importer.handlers.click();
  assert.equal(imports, 1);
  assert.equal(actions.hidden, true);
  response = {ok:false, status:403};
  await logout.handlers.click();
  assert.equal(location.href, '/dashboard.html');
  assert.equal(logout.disabled, false);
  assert.equal(notices.length, 1);
  response = {ok:true, status:200};
  await logout.handlers.click();
  assert.equal(location.href, '/login');
  assert.equal(requests.at(-1).url, '/auth/logout');
  assert.equal(requests.at(-1).options.method, 'POST');
  location.href = '/dashboard.html';
  response = {ok:false, status:401};
  await logout.handlers.click();
  assert.equal(location.href, '/login');
});
