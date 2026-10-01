// Run: node webconsole/certificate-first.test.cjs
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const elements = new Map();
const context = vm.createContext({
  document: { querySelector(selector) {
    if (!elements.has(selector)) elements.set(selector, { innerHTML: '', insertAdjacentHTML() {} });
    return elements.get(selector);
  } }
});
const source = fs.readFileSync(`${__dirname}/certificate-first.js`, 'utf8');
vm.runInContext(source.split("$('#uin-trigger').onclick")[0], context);
const run = code => vm.runInContext(code, context);
run('state.certificates = preview.certificates; state.accounts = preview.accounts; renderRows();');
assert.equal(run('primaryAction(preview.certificates[0])[0]'), 'view');
assert.equal(run('primaryAction(preview.certificates[1])[0]'), 'renew');
assert.equal(run('primaryAction(preview.certificates[2])[0]'), 'issue');
assert.equal(run('primaryAction(preview.certificates[8])[0]'), 'bindings');
assert.equal(run('primaryAction({status:"failing",daysLeft:10})[0]'), 'view');
assert(!elements.get('#certificate-rows').innerHTML.includes('Managed by WeCert'));
assert(!elements.get('#certificate-rows').innerHTML.includes('Production'));
assert(!elements.get('#certificate-rows').innerHTML.includes('Staging'));
assert(elements.get('#certificate-rows').innerHTML.includes('UIN 100012345678'));
assert(elements.get('#certificate-rows').innerHTML.includes('certificate-cell'));
assert(elements.get('#certificate-rows').innerHTML.includes('data-menu="legacy"'));
assert(elements.get('#certificate-rows').innerHTML.includes('4 days ago'));
run('state.collapsed.add("100012345678"); renderRows();');
assert(!elements.get('#certificate-rows').innerHTML.includes('data-name="prod-api-tls"'));
assert(elements.get('#certificate-rows').innerHTML.includes('aria-expanded="false"'));
run('state.selected = "blog"; renderDetail();');
assert(elements.get('#certificate-detail').innerHTML.includes('Binding is required'));
assert.equal(run('escapeHTML("<script>")'), '&lt;script&gt;');
run('state.status = "expiring"');
assert.equal(run('filteredCertificates().length'), 2);
run('state.status = "bindings"');
assert.equal(run('filteredCertificates().length'), 1);
assert.equal(run('filteredCertificates()[0].name'), 'blog');
assert.equal(run('validityLabel({daysLeft:-4})'), 'Expired 4 days ago');
assert.equal(run('validityLabel({daysLeft:0})'), 'Expires today');
assert.equal(run('validityLabel({daysLeft:null,status:"not_issued"})'), 'Not issued yet');
run('state.selected = "legacy"; renderDetail();');
assert(elements.get('#certificate-detail').innerHTML.includes('Expired 4 days ago'));
assert(elements.get('#certificate-detail').innerHTML.includes('<dl class="kv">'));
assert(run(`copyButton(${JSON.stringify('"<test>')})`).includes('&quot;&lt;test&gt;'));
console.log('Certificate UI checks passed');

// Smoke-check the complete startup and event wiring without a browser or network.
function element() {
  const node = {
    innerHTML: '', textContent: '', value: '', dataset: {}, style: {},
    lastChild: { textContent: '' },
    classList: { add() {}, remove() {}, toggle() {}, contains() { return false; } },
    setAttribute() {}, removeAttribute() {}, insertAdjacentHTML() {},
    before() {}, append() {}, prepend() {}, replaceWith() {}, insertAdjacentHTML() {},
  };
  node.parentElement = { before() {} };
  return node;
}
const nodes = new Map();
const events = {};
const document = {
  querySelector(selector) {
    if (!nodes.has(selector)) nodes.set(selector, element());
    return nodes.get(selector);
  },
  querySelectorAll() { return []; }, createElement: element,
  addEventListener(name, handler) { events[name] = handler; }, body: element()
};
vm.runInNewContext(source, { document });
assert.equal(nodes.get('#metric-total').textContent, 9);
assert.equal(typeof nodes.get('#certificate-form').onsubmit, 'function');
assert.equal(typeof events.click, 'function');
assert.equal(nodes.get('#status-filter').hidden, true);
console.log('Full startup checks passed');
