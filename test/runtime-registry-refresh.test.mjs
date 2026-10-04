// Runtime Registry refresh contract, adapter side (XIOT-BUG-0221 /
// xiotbox-gateway#66).
//
// The gateway can now ask any Runtime to re-declare with a neutral
// RUNTIMES.REQUEST. Two invariants matter for OpenClaw:
//
//   1. the frame must actually reach channel.ts. WSSClient.handleMessage has
//      its own type switch, and anything it does not list falls through to
//      "Unknown message type" — the exact two-layer trap already pinned by
//      wss-dispatch.test.mjs for V2.AGENT_PROFILE_SYNC.
//   2. the connected path and the request path must share ONE advertisement
//      implementation. Two builders drift apart within months and the control
//      plane starts showing a declaration nobody runs.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import WSSClient from '../wss_client.js';

function makeClient() {
  return new WSSClient({
    DEVICE_ID: 'test-device',
    GATEWAY_URL: 'ws://127.0.0.1:1',
    OUTBOX_MAX: 10,
  });
}

test('handleMessage dispatches RUNTIMES.REQUEST instead of dropping it', () => {
  const client = makeClient();
  const payload = { request_id: 'req-1', device_id: 'test-device', reason: 'user_refresh' };
  let received = null;
  client.on('RUNTIMES.REQUEST', (p) => { received = p; });
  client.handleMessage({ type: 'RUNTIMES.REQUEST', payload });
  assert.deepEqual(received, payload);
});

test('the built channel advertises its registry from exactly one place', () => {
  const built = readFileSync(new URL('../dist/src/channel.js', import.meta.url), 'utf-8');

  const builderStart = built.indexOf('const advertiseRuntime = () =>');
  assert.ok(builderStart >= 0, 'advertiseRuntime entry point must exist');
  const builderEnd = built.indexOf('};', builderStart);
  const publishSite = built.indexOf("client.sendMessage('RUNTIMES.LIST'");
  assert.ok(publishSite >= 0, "a RUNTIMES.LIST publication must exist");
  assert.ok(
    publishSite > builderStart && publishSite < builderEnd,
    'the only RUNTIMES.LIST write must live inside advertiseRuntime',
  );
  // A second inline publication would be a second builder waiting to drift.
  assert.equal(
    built.indexOf("client.sendMessage('RUNTIMES.LIST'", publishSite + 1),
    -1,
    'RUNTIMES.LIST must be published from advertiseRuntime only',
  );

  const requestSite = built.indexOf("client.on('RUNTIMES.REQUEST'");
  assert.ok(requestSite >= 0, 'channel.ts must listen for RUNTIMES.REQUEST');
  const requestRegion = built.slice(requestSite, requestSite + 1200);
  assert.ok(requestRegion.includes('advertiseRuntime()'), 'the request path re-advertises');
  assert.ok(
    requestRegion.includes("client.sendMessage('RUNTIMES.REQUEST_ACK'"),
    'the request path acknowledges with the echoed request id',
  );

  const connectedSite = built.indexOf("client.on('connected'");
  assert.ok(connectedSite >= 0);
  const connectedRegion = built.slice(connectedSite, built.indexOf("client.on('", connectedSite + 10));
  assert.ok(connectedRegion.includes('advertiseRuntime()'), 'connecting re-advertises');
  assert.ok(
    !connectedRegion.includes("client.sendMessage('RUNTIMES.LIST'"),
    'the connected path must not build its own declaration',
  );
});
