const test = require('node:test');
const assert = require('node:assert/strict');
const { parseWindowsListenerJson } = require('./windows-network.cjs');

test('returns an empty list for an empty query result', () => {
  assert.deepEqual(parseWindowsListenerJson(''), []);
});

test('normalizes a single endpoint object', () => {
  assert.deepEqual(parseWindowsListenerJson('{"Protocol":"TCP","LocalAddress":"127.0.0.1","LocalPort":"3000","OwningProcess":"42"}'), [
    { Protocol: 'TCP', LocalAddress: '127.0.0.1', LocalPort: 3000, OwningProcess: 42 },
  ]);
});

test('keeps valid TCP and UDP entries and drops invalid entries', () => {
  const input = JSON.stringify([
    { Protocol: 'TCP', LocalAddress: '::', LocalPort: 443, OwningProcess: 4 },
    { Protocol: 'UDP', LocalAddress: '0.0.0.0', LocalPort: 53, OwningProcess: 8 },
    { Protocol: 'ICMP', LocalAddress: '0.0.0.0', LocalPort: 53, OwningProcess: 8 },
    { Protocol: 'TCP', LocalAddress: '127.0.0.1', LocalPort: 65536, OwningProcess: 8 },
  ]);

  assert.deepEqual(parseWindowsListenerJson(input), [
    { Protocol: 'TCP', LocalAddress: '::', LocalPort: 443, OwningProcess: 4 },
    { Protocol: 'UDP', LocalAddress: '0.0.0.0', LocalPort: 53, OwningProcess: 8 },
  ]);
});

test('rejects malformed JSON', () => {
  assert.throws(() => parseWindowsListenerJson('{invalid'), SyntaxError);
});
