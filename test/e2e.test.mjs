// E2E crypto unit tests for XIOT-BUG-0050a.
//
// Pins the OGE2E1 envelope, AAD binding, decrypt, device identity signature
// and client trust pinning. These are the invariants 0050a must keep intact:
// the profile/e2e.required_for_commands declaration is only honest if the
// envelope is still authenticated and peers are still signature-verified and
// pinned. No signature verification or pinning is disabled here.

import { after, test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { x25519 } from '@noble/curves/ed25519';

import {
  OpenClawE2E,
  buildEnvelope,
  decryptEnvelope,
} from '../dist/src/e2e.js';

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

function x25519Keypair() {
  // Use the same @noble backend the channel's e2e.ts falls back to when the
  // Node build has no native X25519 ECDH; keys stay raw 32-byte buffers so
  // they are interchangeable with buildEnvelope/decryptEnvelope.
  const priv = crypto.randomBytes(32);
  const pub = Buffer.from(x25519.getPublicKey(priv));
  return { priv, pub };
}

function computeKeyId(pubRaw) {
  return crypto.createHash('sha256').update(pubRaw).digest('hex').slice(0, 16);
}

// Build a self-consistent client identity: ed25519 key + signature over the
// exact OGE2E1 identity payload the channel verifies (ocid|v=1|device=...|...).
function makeClientIdentity(deviceId, clientPubB64, clientKeyId) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const pubDer = publicKey.export({ format: 'der', type: 'spki' });
  const pubDerB64 = pubDer.toString('base64');
  const fingerprint = crypto.createHash('sha256').update(pubDer).digest('hex');
  const sigTs = String(Date.now());
  const sigNonce = crypto.randomBytes(16).toString('hex');
  const sigPayload = Buffer.from(
    `ocid|v=1|device=${deviceId}|peer_pub=${clientPubB64}|peer_key_id=${clientKeyId}|ts=${sigTs}|nonce=${sigNonce}`,
    'utf-8',
  );
  const sig = crypto.sign(null, sigPayload, privateKey);
  return {
    privateKey,
    pubDerB64,
    fingerprint,
    sigB64: sig.toString('base64'),
    sigTs,
    sigNonce,
  };
}

// ── OGE2E1 envelope ──

test('OGE2E1 envelope round-trips through decrypt', () => {
  const { priv, pub } = x25519Keypair();
  const envelope = buildEnvelope(
    Buffer.from('hello xiotbox', 'utf-8'),
    pub,
    'key-abc123',
    null,
    'session-1',
    1,
  );
  assert.equal(envelope.magic, 'OGE2E1');
  assert.equal(envelope.version, 1);
  assert.equal(envelope.alg, 'AES-256-GCM');
  assert.equal(envelope.key_id, 'key-abc123');
  assert.equal(envelope.session_id, 'session-1');
  assert.equal(envelope.enc_version, 1);
  const plaintext = decryptEnvelope(envelope, priv, null);
  assert.equal(plaintext.toString('utf-8'), 'hello xiotbox');
});

test('buildEnvelope rejects a malformed receiver public key', () => {
  assert.throws(
    () => buildEnvelope(Buffer.from('x'), Buffer.from('too-short'), 'k'),
    /invalid_pubkey_len/,
  );
});

test('decryptEnvelope rejects a non-OGE2E1 envelope', () => {
  const { priv } = x25519Keypair();
  assert.throws(
    () => decryptEnvelope({ magic: 'NOT-E2E', version: 1 }, priv),
    /invalid_envelope/,
  );
  assert.throws(
    () => decryptEnvelope({ magic: 'OGE2E1', version: 999 }, priv),
    /invalid_envelope/,
  );
});

// ── AAD ──

test('buildAad binds direction/device/thread/command/type/seq deterministically', () => {
  const e2e = new OpenClawE2E({});
  const aad = e2e.buildAad({
    direction: 'in',
    device_id: 'dev-1',
    thread_id: 't1',
    command_id: 'cmd-1',
    content_type: 'text',
    chunk_seq: 0,
  });
  assert.equal(
    aad.toString('utf-8'),
    'oc|v=1|dir=in|device=dev-1|thread=t1|cmd=cmd-1|type=text|seq=0',
  );
});

test('AAD is authenticated: tampering the envelope AAD fails decryption', () => {
  const { priv, pub } = x25519Keypair();
  const aad = Buffer.from(
    'oc|v=1|dir=in|device=dev-1|thread=main|cmd=c1|type=text|seq=0',
    'utf-8',
  );
  const envelope = buildEnvelope(Buffer.from('secret'), pub, 'k', aad);
  // Verify the honest envelope decrypts.
  assert.equal(decryptEnvelope(envelope, priv, null).toString('utf-8'), 'secret');
  // Swap in a different AAD: GCM authentication must reject it.
  const tampered = { ...envelope };
  tampered.aad_b64 = Buffer.from(
    'oc|v=1|dir=in|device=dev-1|thread=main|cmd=c1|type=text|seq=1',
    'utf-8',
  ).toString('base64');
  assert.throws(() => decryptEnvelope(tampered, priv, null));
});

// ── decrypt ──

test('decrypt fails with the wrong receiver private key', () => {
  const { pub } = x25519Keypair();
  const other = x25519Keypair();
  const envelope = buildEnvelope(Buffer.from('secret'), pub, 'k');
  assert.throws(() => decryptEnvelope(envelope, other.priv, null));
});

test('decrypt fails when the ciphertext is tampered', () => {
  const { priv, pub } = x25519Keypair();
  const envelope = buildEnvelope(Buffer.from('secret'), pub, 'k');
  const ct = Buffer.from(envelope.ct_b64, 'base64');
  ct[0] ^= 0xff;
  envelope.ct_b64 = ct.toString('base64');
  assert.throws(() => decryptEnvelope(envelope, priv, null));
});

// ── identity signature ──

test('helloPayload signs the peer key with the device ed25519 identity', () => {
  const dir = tempDir('xiot-e2e-identity-');
  const e2e = new OpenClawE2E({
    DEVICE_ID: 'dev-sig-1',
    E2E_KEY_PATH: path.join(dir, 'e2e.json'),
    IDENTITY_KEY_PATH: path.join(dir, 'identity.json'),
  });
  e2e.init();

  const payload = e2e.helloPayload();
  assert.ok(payload, 'hello payload is produced once the keypair exists');
  assert.ok(payload.pubkey, 'peer public key is present');
  assert.ok(payload.identity_pub, 'identity public key is present');
  assert.equal(payload.identity_sig_alg, 'ed25519');
  assert.ok(payload.identity_sig, 'identity signature is present');

  // Reconstruct the exact signed bytes and verify the signature.
  const signed = Buffer.from(
    `ocid|v=1|device=dev-sig-1|peer_pub=${payload.pubkey}|peer_key_id=${payload.key_id}|ts=${payload.identity_sig_ts}|nonce=${payload.identity_sig_nonce}`,
    'utf-8',
  );
  const pubKey = crypto.createPublicKey({
    key: Buffer.from(payload.identity_pub, 'base64'),
    format: 'der',
    type: 'spki',
  });
  assert.equal(
    crypto.verify(null, signed, pubKey, Buffer.from(payload.identity_sig, 'base64')),
    true,
    'identity signature verifies against the declared identity public key',
  );

  // Fingerprint must be the sha256 of the identity public key (full hex).
  const fingerprint = crypto
    .createHash('sha256')
    .update(Buffer.from(payload.identity_pub, 'base64'))
    .digest('hex');
  assert.equal(payload.identity_fingerprint, fingerprint);
});

// ── trust pinning ──

function commandPeerPayload(deviceId, clientPub, clientKeyId, identity, commandId) {
  const resolvedCommandId = commandId || 'cmd-proof';
  const canonicalAad = Buffer.from(
    `oc|v=2|dir=c2p|device=${deviceId}|thread=main|cmd=${resolvedCommandId}|type=text/markdown|seq=0`,
    'utf-8',
  );
  const receiver = x25519Keypair();
  const envelope = buildEnvelope(
    Buffer.from('proof-only'),
    receiver.pub,
    computeKeyId(receiver.pub),
    canonicalAad,
    'session-proof',
    2,
  );
  const envelopeCanonical = [
    envelope.magic ?? '',
    envelope.version ?? '',
    envelope.alg ?? '',
    envelope.key_id ?? '',
    envelope.nonce_b64 ?? '',
    envelope.ek_b64 ?? '',
    envelope.ct_b64 ?? '',
    envelope.aad_b64 ?? '',
    envelope.session_id ?? '',
    envelope.enc_version ?? '',
  ];
  const envelopeSha256 = crypto
    .createHash('sha256')
    .update(JSON.stringify(envelopeCanonical))
    .digest('hex');
  const commandSigTs = String(Date.now());
  const commandSigNonce = crypto.randomBytes(16).toString('hex');
  const commandSigPayload = Buffer.from(
    `occmd|v=1|device=${deviceId}|peer_pub=${clientPub.toString('base64')}|peer_key_id=${clientKeyId}|cmd=${resolvedCommandId}|aad_b64=${canonicalAad.toString('base64')}|envelope_sha256=${envelopeSha256}|ts=${commandSigTs}|nonce=${commandSigNonce}`,
    'utf-8',
  );
  const commandSig = crypto.sign(null, commandSigPayload, identity.privateKey);
  return {
    payload: {
      client_public_key: clientPub.toString('base64'),
      client_key_id: clientKeyId,
      client_identity_public_key: identity.pubDerB64,
      client_identity_fingerprint: identity.fingerprint,
      client_identity_sig: identity.sigB64,
      client_identity_sig_alg: 'ed25519',
      client_identity_sig_ts: identity.sigTs,
      client_identity_sig_nonce: identity.sigNonce,
      client_command_identity_sig: commandSig.toString('base64'),
      client_command_identity_sig_alg: 'ed25519',
      client_command_identity_sig_ts: commandSigTs,
      client_command_identity_sig_nonce: commandSigNonce,
    },
    command: {
      commandId: resolvedCommandId,
      canonicalAad,
      envelope,
    },
  };
}

test('trust pinning enrolls the first client identity and rejects a changed one', () => {
  const dir = tempDir('xiot-e2e-trust-');
  const e2e = new OpenClawE2E({
    DEVICE_ID: 'dev-trust-1',
    TRUST_PATH: path.join(dir, 'trust.json'),
    ALLOW_NEW_CLIENT_IDENTITIES: false,
  });

  const firstX = x25519Keypair();
  const firstKeyId = computeKeyId(firstX.pub);
  const firstIdentity = makeClientIdentity(
    'dev-trust-1',
    firstX.pub.toString('base64'),
    firstKeyId,
  );

  // First resolution: no pins exist yet, so the identity is enrolled.
  const firstCommand = commandPeerPayload('dev-trust-1', firstX.pub, firstKeyId, firstIdentity, 'cmd-first');
  const first = e2e.resolveCommandPeerFromPayload(firstCommand.payload, firstCommand.command);
  assert.ok(first, 'first identity is pinned');
  assert.equal(first.publicKey, firstX.pub.toString('base64'));
  assert.equal(e2e.peerTrustError, '');

  // A different client identity must be rejected without enrolling.
  const secondX = x25519Keypair();
  const secondKeyId = computeKeyId(secondX.pub);
  const secondIdentity = makeClientIdentity(
    'dev-trust-1',
    secondX.pub.toString('base64'),
    secondKeyId,
  );
  const secondCommand = commandPeerPayload('dev-trust-1', secondX.pub, secondKeyId, secondIdentity, 'cmd-second');
  const second = e2e.resolveCommandPeerFromPayload(secondCommand.payload, secondCommand.command);
  assert.equal(second, null);
  assert.equal(e2e.peerTrustError, 'client_identity_changed');
});

test('trust pinning rejects an identity whose fingerprint does not match its key', () => {
  const dir = tempDir('xiot-e2e-trust-');
  const e2e = new OpenClawE2E({
    DEVICE_ID: 'dev-trust-2',
    TRUST_PATH: path.join(dir, 'trust.json'),
    ALLOW_NEW_CLIENT_IDENTITIES: false,
  });

  const clientX = x25519Keypair();
  const clientKeyId = computeKeyId(clientX.pub);
  const identity = makeClientIdentity(
    'dev-trust-2',
    clientX.pub.toString('base64'),
    clientKeyId,
  );
  const command = commandPeerPayload('dev-trust-2', clientX.pub, clientKeyId, identity, 'cmd-fingerprint');
  // Corrupt the claimed fingerprint while keeping a valid command proof.
  command.payload.client_identity_fingerprint = '0'.repeat(64);

  assert.equal(e2e.resolveCommandPeerFromPayload(command.payload, command.command), null);
  // XIOT-BUG-0050b (PLAN-0008 §4.5): the identity material parses, but the
  // authenticity/trust check failed — a runtime-local policy rejection.
  assert.equal(e2e.peerTrustError, 'signature_invalid');
});

test('trust pinning re-enrolls an additional identity when enrollment is allowed', () => {
  const dir = tempDir('xiot-e2e-trust-');
  const e2e = new OpenClawE2E({
    DEVICE_ID: 'dev-trust-3',
    TRUST_PATH: path.join(dir, 'trust.json'),
    ALLOW_NEW_CLIENT_IDENTITIES: true,
  });

  const firstX = x25519Keypair();
  const firstKeyId = computeKeyId(firstX.pub);
  const firstIdentity = makeClientIdentity(
    'dev-trust-3',
    firstX.pub.toString('base64'),
    firstKeyId,
  );
  const firstCommand = commandPeerPayload('dev-trust-3', firstX.pub, firstKeyId, firstIdentity, 'cmd-enroll-first');
  assert.ok(e2e.resolveCommandPeerFromPayload(firstCommand.payload, firstCommand.command));

  const secondX = x25519Keypair();
  const secondKeyId = computeKeyId(secondX.pub);
  const secondIdentity = makeClientIdentity(
    'dev-trust-3',
    secondX.pub.toString('base64'),
    secondKeyId,
  );
  const secondCommand = commandPeerPayload('dev-trust-3', secondX.pub, secondKeyId, secondIdentity, 'cmd-enroll-second');
  const second = e2e.resolveCommandPeerFromPayload(secondCommand.payload, secondCommand.command);
  assert.ok(second, 'additional identity is enrolled when allowed');
  assert.equal(e2e.peerTrustError, '');
});

// ── XIOT-BUG-0118: optional |preset=<value> AAD segment ──

test('buildAad appends the preset segment only for a non-empty permission_preset', () => {
  const e2e = new OpenClawE2E({});
  const base = {
    direction: 'in',
    device_id: 'dev-1',
    thread_id: 'main',
    command_id: 'cmd-1',
    content_type: 'text',
    chunk_seq: 0,
  };
  assert.equal(
    e2e.buildAad({ ...base, permission_preset: 'auto-approve' }).toString('utf-8'),
    'oc|v=1|dir=in|device=dev-1|thread=main|cmd=cmd-1|type=text|seq=0|preset=auto-approve',
  );
  // Absent, null, empty and whitespace-only are canonical "no preset":
  // byte-identical to the legacy AAD, never an empty segment.
  const legacy = e2e.buildAad(base).toString('utf-8');
  assert.equal(e2e.buildAad({ ...base, permission_preset: undefined }).toString('utf-8'), legacy);
  assert.equal(e2e.buildAad({ ...base, permission_preset: null }).toString('utf-8'), legacy);
  assert.equal(e2e.buildAad({ ...base, permission_preset: '' }).toString('utf-8'), legacy);
  assert.equal(e2e.buildAad({ ...base, permission_preset: '   ' }).toString('utf-8'), legacy);
});

test('a preset sealed into the AAD cannot be tampered, deleted or injected in flight', () => {
  const e2e = new OpenClawE2E({});
  const { priv, pub } = x25519Keypair();
  const base = {
    direction: 'in',
    device_id: 'dev-1',
    thread_id: 'main',
    command_id: 'cmd-preset',
    content_type: 'text',
    chunk_seq: 0,
  };
  const boundAad = e2e.buildAad({ ...base, permission_preset: 'auto-approve' });
  // v2 strictness is derived from the authenticated AAD grammar, not from
  // the unauthenticated envelope.enc_version selector.
  const envelope = buildEnvelope(Buffer.from('secret'), pub, 'k', boundAad, 's', 2);
  // Legitimate: the same preset-bound AAD verifies.
  assert.equal(decryptEnvelope(envelope, priv, boundAad).toString('utf-8'), 'secret');
  // Replaced preset in flight: mismatch.
  assert.throws(() =>
    decryptEnvelope(envelope, priv, e2e.buildAad({ ...base, permission_preset: 'danger-full-access' })),
  );
  // Deleted preset in flight: the legacy AAD cannot verify preset-bound ciphertext.
  assert.throws(() => decryptEnvelope(envelope, priv, e2e.buildAad(base)));

  // Injected preset on a legacy frame: the preset-bound AAD cannot verify
  // ciphertext sealed under the legacy AAD.
  const legacyEnvelope = buildEnvelope(Buffer.from('secret'), pub, 'k', e2e.buildAad(base), 's', 2);
  assert.throws(() =>
    decryptEnvelope(legacyEnvelope, priv, e2e.buildAad({ ...base, permission_preset: 'auto-approve' })),
  );
  // Legacy traffic stays compatible.
  assert.equal(decryptEnvelope(legacyEnvelope, priv, e2e.buildAad(base)).toString('utf-8'), 'secret');
});

test('strict AAD verification cannot be downgraded by enc_version tampering', () => {
  const e2e = new OpenClawE2E({});
  const { priv, pub } = x25519Keypair();
  const base = {
    direction: 'in',
    device_id: 'dev-downgrade',
    thread_id: 'main',
    command_id: 'cmd-downgrade',
    content_type: 'text',
    chunk_seq: 0,
    enc_v: 2,
  };
  const boundAad = e2e.buildAad({ ...base, permission_preset: 'auto-approve' });
  const envelope = buildEnvelope(Buffer.from('secret'), pub, 'k', boundAad, 's', 2);
  const mismatchedLocalAad = e2e.buildAad({
    ...base,
    enc_v: 1,
    permission_preset: 'danger-full-access',
  });

  for (const tamperedVersion of [1, undefined, 'not-a-version']) {
    const tampered = { ...envelope };
    if (tamperedVersion === undefined) delete tampered.enc_version;
    else tampered.enc_version = tamperedVersion;
    assert.throws(
      () => decryptEnvelope(tampered, priv, mismatchedLocalAad),
      /e2e_aad_mismatch/,
    );
  }
});
