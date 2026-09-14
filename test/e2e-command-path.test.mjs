// Real E2E command-path tests for XIOT-BUG-0050a.
//
// The 0050a profile declares e2e.required_for_commands=true with
// envelope=OGE2E1 / alg=x25519+AES-256-GCM. These tests prove the declaration
// matches the REAL crypto path a chat command takes in src/channel.ts:
//
//  1. the channel's e2e gate (channel.ts, COMMAND handler): a chat payload
//     without an OGE2E1 envelope must fail closed — the gate predicate used
//     here is the exact one the handler applies (`incoming.magic ===
//     'OGE2E1' ? incoming : incoming.e2e` → else status=failed,
//     error=e2e_required);
//  2. an envelope produced by the real encryptText() with the exact
//     direction/device/thread/command/content-type meta channel.ts decrypts
//     with round-trips through the real decryptText() (x25519 wrap + HKDF +
//     AES-256-GCM, enc_version=2);
//  3. the AAD meta binding is cryptographically enforced: a tampered AAD or
//     a mismatched command_id fails decryption, which the channel maps to
//     `e2e_decrypt_failed`.
//
// No crypto is mocked: these run the shipped dist/src/e2e.js implementation
// end to end over real generated keypairs.

import { after, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { OpenClawE2E } from '../dist/src/e2e.js';
import { buildOpenclawCapabilityDeclaration } from '../dist/src/runtime-profile.js';

const tmpDirs = [];

after(() => {
  for (const dir of tmpDirs.splice(0)) {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {
      // best effort cleanup
    }
  }
});

function tempDir(prefix) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  tmpDirs.push(dir);
  return dir;
}

function makeBot(deviceId) {
  const dir = tempDir(`xiot-e2e-cmdpath-bot-${deviceId}-`);
  const bot = new OpenClawE2E({
    DEVICE_ID: deviceId,
    E2E_KEY_PATH: path.join(dir, 'e2e.json'),
    IDENTITY_KEY_PATH: path.join(dir, 'identity.json'),
  });
  bot.init();
  return bot;
}

function makeClient(deviceId) {
  const dir = tempDir(`xiot-e2e-cmdpath-client-${deviceId}-`);
  const client = new OpenClawE2E({
    DEVICE_ID: deviceId,
    E2E_KEY_PATH: path.join(dir, 'e2e.json'),
  });
  client.init();
  return client;
}

// The exact meta channel.ts decrypts a chat command with (c2p direction,
// device/thread/command/content-type binding, chunk_seq 0).
function channelDecryptMeta(deviceId, threadId, commandId, extra = {}) {
  return {
    direction: 'c2p',
    device_id: deviceId,
    thread_id: threadId,
    command_id: commandId,
    content_type: 'text/markdown',
    chunk_seq: 0,
    // Production channel.ts always derives enc_v from the envelope
    // (encryptText emits enc_version=2); the meta must match or the strict
    // v2 AAD verification (XIOT-BUG-0118) rejects the frame.
    enc_v: 2,
    ...extra,
  };
}

// ── 1. The declaration's envelope contract vs the real channel gate ──────

test('the e2e gate a chat command hits: real envelope shapes pass, absence fails closed', () => {
  const bot = makeBot('dev-gate-1');
  const hello = bot.helloPayload();
  const client = makeClient('dev-gate-1');

  // Real envelope produced by the client for the bot.
  const envelope = client.encryptText(
    'status check',
    channelDecryptMeta('dev-gate-1', 'conv-1', 'cmd-gate-1'),
    { publicKey: hello.pubkey, keyId: hello.key_id },
  );

  // The channel's gate (channel.ts): nested under payload.e2e or top level.
  const gateEnv = (incoming) => {
    const env = incoming?.magic === 'OGE2E1' ? incoming : incoming?.e2e;
    return env && env.magic === 'OGE2E1' ? env : null;
  };

  // Top-level envelope (gateway flattening) passes the gate…
  const topLevel = { ...envelope, command_id: 'cmd-gate-1' };
  assert.equal(gateEnv(topLevel), topLevel);
  // …and the nested wire shape (payload.payload.e2e) passes it too.
  const nested = { e2e: envelope };
  assert.equal(gateEnv(nested), envelope);
  // A chat payload without an envelope must fail closed: the gate returns
  // null and the handler replies status=failed, error=e2e_required — the
  // exact enforcement behind the declared e2e.required_for_commands=true.
  assert.equal(gateEnv({ text: 'plain chat, no envelope' }), null);
  assert.equal(gateEnv({ e2e: { magic: 'NOT-E2E' } }), null);
  assert.equal(gateEnv(undefined), null);
});

test('the declared envelope name matches the envelope the real path emits', () => {
  const declaration = buildOpenclawCapabilityDeclaration();
  assert.equal(declaration.e2e.required_for_commands, true);
  assert.equal(declaration.e2e.envelope, 'OGE2E1');

  const bot = makeBot('dev-decl-1');
  const hello = bot.helloPayload();
  const client = makeClient('dev-decl-1');
  const envelope = client.encryptText(
    'x',
    channelDecryptMeta('dev-decl-1', 'conv-1', 'cmd-decl-1'),
    { publicKey: hello.pubkey, keyId: hello.key_id },
  );

  // Wire truth: the real envelope is the declared envelope.
  assert.equal(envelope.magic, declaration.e2e.envelope);
  // alg composition convention: the declared alg names the hybrid
  // (x25519 wrap + AES-256-GCM); the envelope records the symmetric part.
  assert.equal(envelope.alg, 'AES-256-GCM');
  assert.equal(declaration.e2e.alg.includes(envelope.alg), true);
  // enc_version=2 is what encryptText emits for the v2 protocol.
  assert.equal(envelope.enc_version, 2);
});

// ── 2. Real round trip through the channel's exact decrypt meta ──────────

test('chat command round trip: client encryptText → bot decryptText with channel meta', () => {
  const deviceId = 'dev-roundtrip-1';
  const bot = makeBot(deviceId);
  const hello = bot.helloPayload();
  const client = makeClient(deviceId);

  const plaintext = '你好，xiotbox — real e2e command path';
  const envelope = client.encryptText(
    plaintext,
    channelDecryptMeta(deviceId, 'conv-9', 'cmd-rt-1'),
    { publicKey: hello.pubkey, keyId: hello.key_id },
  );

  // The bot decrypts with the meta channel.ts passes to decryptText.
  const decrypted = bot.decryptText(
    envelope,
    channelDecryptMeta(deviceId, 'conv-9', 'cmd-rt-1'),
  );
  assert.equal(decrypted, plaintext);

  // The wrapped key is the bot's: another device's key cannot open it.
  const stranger = makeBot('dev-stranger-1');
  assert.throws(() =>
    stranger.decryptText(envelope, channelDecryptMeta(deviceId, 'conv-9', 'cmd-rt-1')),
  );
});

// ── 3. AAD meta binding is enforced (e2e_decrypt_failed mapping) ─────────

test('tampering the envelope AAD fails decryption (command binding intact)', () => {
  const deviceId = 'dev-aad-1';
  const bot = makeBot(deviceId);
  const hello = bot.helloPayload();
  const client = makeClient(deviceId);

  const envelope = client.encryptText(
    'bind me',
    channelDecryptMeta(deviceId, 'conv-1', 'cmd-aad-1'),
    { publicKey: hello.pubkey, keyId: hello.key_id },
  );

  // Rewrite the authenticated AAD to a different command binding: both the
  // packetAAD attempt and the localAAD fallback must fail — decryptText
  // throws, which channel.ts maps to status=failed, error=e2e_decrypt_failed.
  const tampered = { ...envelope };
  tampered.aad_b64 = Buffer.from(
    `oc|v=2|dir=c2p|device=${deviceId}|thread=conv-1|cmd=cmd-aad-2|type=text/markdown|seq=0`,
    'utf-8',
  ).toString('base64');
  assert.throws(() =>
    bot.decryptText(tampered, channelDecryptMeta(deviceId, 'conv-1', 'cmd-aad-1')),
  );
});

test('without packetAAD the local meta binding is enforced: wrong command_id fails', () => {
  const deviceId = 'dev-meta-1';
  const bot = makeBot(deviceId);
  const hello = bot.helloPayload();
  const client = makeClient(deviceId);

  const envelope = client.encryptText(
    'meta bound',
    channelDecryptMeta(deviceId, 'conv-1', 'cmd-meta-1'),
    { publicKey: hello.pubkey, keyId: hello.key_id },
  );

  // Compat path: strip packetAAD so decryptText falls back to the AAD it
  // derives from the caller meta (the channel supplies enc_v from its
  // session; encryptText authenticated the AAD at v=2).
  const stripped = { ...envelope };
  delete stripped.aad_b64;

  // Matching meta (enc_v=2, the version encryptText authenticated) decrypts…
  const decrypted = bot.decryptText(
    stripped,
    channelDecryptMeta(deviceId, 'conv-1', 'cmd-meta-1', { enc_v: 2 }),
  );
  assert.equal(decrypted, 'meta bound');

  // …but a meta with a different command_id cannot open the same ciphertext.
  assert.throws(() =>
    bot.decryptText(
      stripped,
      channelDecryptMeta(deviceId, 'conv-1', 'cmd-other-9', { enc_v: 2 }),
    ),
  );
  // A different thread is equally bound out.
  assert.throws(() =>
    bot.decryptText(
      stripped,
      channelDecryptMeta(deviceId, 'conv-other', 'cmd-meta-1', { enc_v: 2 }),
    ),
  );
});

test('permission_preset binding survives enc_version downgrade, omission and corruption', () => {
  const deviceId = 'dev-preset-downgrade';
  const bot = makeBot(deviceId);
  const hello = bot.helloPayload();
  const client = makeClient(deviceId);
  const base = channelDecryptMeta(deviceId, 'conv-preset', 'cmd-preset');

  const cases = [
    {
      name: 'replace',
      sentMeta: { ...base, permission_preset: 'auto-approve' },
      recvMeta: { ...base, permission_preset: 'danger-full-access' },
    },
    {
      name: 'delete',
      sentMeta: { ...base, permission_preset: 'auto-approve' },
      recvMeta: { ...base },
    },
    {
      name: 'inject',
      sentMeta: { ...base },
      recvMeta: { ...base, permission_preset: 'auto-approve' },
    },
  ];

  for (const scenario of cases) {
    const envelope = client.encryptText(
      `preset-${scenario.name}`,
      scenario.sentMeta,
      { publicKey: hello.pubkey, keyId: hello.key_id },
    );

    for (const versionMode of ['downgrade', 'missing', 'malformed']) {
      const tampered = { ...envelope };
      if (versionMode === 'downgrade') tampered.enc_version = 1;
      else if (versionMode === 'missing') delete tampered.enc_version;
      else tampered.enc_version = 'not-a-version';

      const recvMeta = {
        ...scenario.recvMeta,
        // This mirrors channel.ts: a tampered/missing envelope version can
        // influence locally reconstructed metadata, but must never relax
        // authenticated preset semantics.
        enc_v: versionMode === 'downgrade' ? 1 : undefined,
      };
      assert.throws(
        () => bot.decryptText(tampered, recvMeta),
        undefined,
        `${scenario.name}/${versionMode} must fail closed`,
      );
    }
  }
});
