import crypto from 'crypto';
import { x25519 } from '@noble/curves/ed25519';
import fs from 'fs';
import os from 'os';
import path from 'path';
import http from 'http';
import https from 'https';

const E2E_MAGIC = 'OGE2E1';
const E2E_VERSION = 1;
const E2E_ALG = 'AES-256-GCM';
const E2E_KEY_ALG = 'x25519';
const DEFAULT_THREAD_ID = 'main';
const HKDF_INFO = Buffer.from('OGE2E1-wrap', 'utf-8');

const PUBKEY_LEN = 32;
const WRAP_NONCE_LEN = 12;
const CONTENT_KEY_LEN = 32;
const GCM_TAG_LEN = 16;
const HAS_NATIVE_X25519 = (() => {
  try {
    return typeof crypto.getCurves === 'function' && crypto.getCurves().includes('x25519');
  } catch (_err) {
    return false;
  }
})();

function b64e(buf: Buffer): string {
  return Buffer.from(buf).toString('base64');
}

function b64d(value: string): Buffer {
  return Buffer.from(value || '', 'base64');
}

function looksLikeHex(value?: string): boolean {
  if (!value) return false;
  const v = value.trim();
  if (!v || v.length % 2) return false;
  return /^[0-9a-fA-F]+$/.test(v);
}

function decodePubkey(pubkey: string): Buffer | null {
  if (!pubkey) return null;
  const raw = pubkey.trim();
  if (!raw) return null;
  try {
    if (looksLikeHex(raw)) {
      return Buffer.from(raw, 'hex');
    }
    return b64d(raw);
  } catch (_err) {
    return null;
  }
}

function normalizeThreadId(value?: string | null): string {
  const normalized = String(value || '').trim();
  return normalized || DEFAULT_THREAD_ID;
}

function computeKeyId(pubRaw: Buffer): string {
  return crypto.createHash('sha256').update(pubRaw).digest('hex').slice(0, 16);
}

function computeFingerprint(pubRaw: Buffer): string {
  return computeKeyId(pubRaw);
}

function computeFingerprintFull(pubRaw: Buffer): string {
  return crypto.createHash('sha256').update(pubRaw).digest('hex');
}

function aesGcmEncrypt(key: Buffer, nonce: Buffer, plaintext: Buffer, aad?: Buffer | null): Buffer {
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
  if (aad && aad.length) {
    cipher.setAAD(aad);
  }
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([ct, tag]);
}

function aesGcmDecrypt(key: Buffer, nonce: Buffer, ciphertext: Buffer, aad?: Buffer | null): Buffer {
  const ct = ciphertext.slice(0, Math.max(0, ciphertext.length - GCM_TAG_LEN));
  const tag = ciphertext.slice(Math.max(0, ciphertext.length - GCM_TAG_LEN));
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
  if (aad && aad.length) {
    decipher.setAAD(aad);
  }
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

function x25519Keypair(): { priv: Buffer; pub: Buffer } {
  if (HAS_NATIVE_X25519) {
    const ecdh = crypto.createECDH('x25519');
    ecdh.generateKeys();
    return { priv: ecdh.getPrivateKey(), pub: ecdh.getPublicKey() };
  }
  const priv = crypto.randomBytes(32);
  const pub = Buffer.from(x25519.getPublicKey(priv));
  return { priv, pub };
}

function x25519SharedSecret(priv: Buffer, pub: Buffer): Buffer {
  if (HAS_NATIVE_X25519) {
    const ecdh = crypto.createECDH('x25519');
    ecdh.setPrivateKey(priv);
    return ecdh.computeSecret(pub);
  }
  return Buffer.from(x25519.getSharedSecret(priv, pub));
}

export function buildEnvelope(
  plaintext: Buffer,
  receiverPubkey: Buffer,
  keyId: string,
  aad?: Buffer | null,
  sessionId?: string | null,
  encVersion?: number,
): Record<string, any> {
  if (!receiverPubkey || receiverPubkey.length !== PUBKEY_LEN) {
    throw new Error('invalid_pubkey_len');
  }
  const contentKey = crypto.randomBytes(CONTENT_KEY_LEN);
  const contentNonce = crypto.randomBytes(12);
  const ciphertext = aesGcmEncrypt(contentKey, contentNonce, plaintext, aad);

  const { priv: epkPriv, pub: epkPub } = x25519Keypair();
  const shared = x25519SharedSecret(epkPriv, receiverPubkey);
  const wrapKey = Buffer.from(crypto.hkdfSync('sha256', shared, Buffer.alloc(0), HKDF_INFO, 32));
  const wrapNonce = crypto.randomBytes(WRAP_NONCE_LEN);
  const wrappedKey = aesGcmEncrypt(wrapKey, wrapNonce, contentKey, null);

  const ekBlob = Buffer.concat([epkPub, wrapNonce, wrappedKey]);
  const envelope: Record<string, any> = {
    magic: E2E_MAGIC,
    version: E2E_VERSION,
    alg: E2E_ALG,
    key_id: keyId || '',
    nonce_b64: b64e(contentNonce),
    ek_b64: b64e(ekBlob),
    ct_b64: b64e(ciphertext),
  };
  if (sessionId) {
    envelope.session_id = sessionId;
  }
  if (encVersion !== undefined && encVersion !== null) {
    envelope.enc_version = encVersion;
  }
  if (aad && aad.length) {
    envelope.aad_b64 = b64e(aad);
  }
  return envelope;
}

export function decryptEnvelope(
  envelope: Record<string, any>,
  privRaw: Buffer,
  aad?: Buffer | null,
): Buffer {
  if (!envelope || envelope.magic !== E2E_MAGIC || envelope.version !== E2E_VERSION) {
    throw new Error('invalid_envelope');
  }

  // Read enc_version and session_id for diagnostics
  const encVersion = envelope.enc_version ?? 1;
  const keyIdShort = (envelope.key_id || '').slice(0, 8);
  const sessionIdShort = (envelope.session_id || 'none').slice(0, 8);
  console.log(`[E2E] Decrypt attempt: enc_v=${encVersion} key_id=${keyIdShort} session_id=${sessionIdShort}`);

  const ekBlob = b64d(envelope.ek_b64 || '');
  if (ekBlob.length < PUBKEY_LEN + WRAP_NONCE_LEN + GCM_TAG_LEN) {
    throw new Error('invalid_ek');
  }
  const epk = ekBlob.slice(0, PUBKEY_LEN);
  const wrapNonce = ekBlob.slice(PUBKEY_LEN, PUBKEY_LEN + WRAP_NONCE_LEN);
  const wrapped = ekBlob.slice(PUBKEY_LEN + WRAP_NONCE_LEN);
  const shared = x25519SharedSecret(privRaw, epk);
  const wrapKey = Buffer.from(crypto.hkdfSync('sha256', shared, Buffer.alloc(0), HKDF_INFO, 32));
  const contentKey = aesGcmDecrypt(wrapKey, wrapNonce, wrapped, null);

  const nonce = b64d(envelope.nonce_b64 || '');
  const ciphertext = b64d(envelope.ct_b64 || '');
  const envAad = envelope.aad_b64 ? b64d(envelope.aad_b64) : null;

  // Prioritize envelope AAD (packetAAD) over provided AAD (localAAD)
  // This fixes multi-device scenarios where device_id differs.
  // XIOT-BUG-0118: for the canonical v2 grammar a mismatch between the
  // caller-derived AAD (from THIS dispatch frame) and the envelope-carried
  // AAD is a protocol violation — the carried value must never override
  // canonical verification, otherwise the authenticated dispatch context
  // (including permission_preset) is tamperable. Legacy envelopes
  // (enc_version < 2) keep the lenient fallback.
  if (aad && envAad && !aad.equals(envAad)) {
    if ((envelope.enc_version ?? 1) >= 2) {
      throw new Error('e2e_aad_mismatch');
    }
    console.warn('[E2E] AAD mismatch, using envelope AAD', {
      providedHash: aad.toString('hex').slice(0, 24),
      envelopeHash: envAad.toString('hex').slice(0, 24),
    });
  }
  const aadToUse = envAad || aad || null;  // Prioritize envelope AAD
  return aesGcmDecrypt(contentKey, nonce, ciphertext, aadToUse);
}

function resolveKeyPath(cfg: any, deviceId: string): string {
  if (cfg?.E2E_KEY_PATH) return cfg.E2E_KEY_PATH;
  const base = path.join(os.homedir(), '.openclaw');
  return path.join(base, `xiotbox_e2e_${deviceId}.json`);
}

function resolveIdentityPath(cfg: any, deviceId: string): string {
  if (cfg?.IDENTITY_KEY_PATH) return cfg.IDENTITY_KEY_PATH;
  const base = path.join(os.homedir(), '.openclaw');
  return path.join(base, `xiotbox_identity_${deviceId}.json`);
}

function loadIdentity(cfg: any, deviceId: string): { privDer: Buffer; pubDer: Buffer } | null {
  const keyPath = resolveIdentityPath(cfg, deviceId);
  if (!fs.existsSync(keyPath)) return null;
  try {
    const raw = JSON.parse(fs.readFileSync(keyPath, 'utf-8'));
    const privDer = b64d(raw.priv_b64 || '');
    const pubDer = b64d(raw.pub_b64 || '');
    if (!privDer.length || !pubDer.length) return null;
    return { privDer, pubDer };
  } catch (_err) {
    return null;
  }
}

function saveIdentity(cfg: any, deviceId: string, privDer: Buffer, pubDer: Buffer): { privDer: Buffer; pubDer: Buffer } {
  const keyPath = resolveIdentityPath(cfg, deviceId);
  const dir = path.dirname(keyPath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const payload = {
    v: 1,
    alg: 'ed25519',
    priv_b64: b64e(privDer),
    pub_b64: b64e(pubDer),
  };
  fs.writeFileSync(keyPath, JSON.stringify(payload));
  try {
    fs.chmodSync(keyPath, 0o600);
  } catch (_err) {
    // best effort
  }
  return { privDer, pubDer };
}

function generateIdentity(cfg: any, deviceId: string): { privDer: Buffer; pubDer: Buffer } {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const privDer = privateKey.export({ format: 'der', type: 'pkcs8' });
  const pubDer = publicKey.export({ format: 'der', type: 'spki' });
  return saveIdentity(cfg, deviceId, privDer, pubDer);
}

function ensureIdentity(cfg: any, deviceId: string): { privDer: Buffer; pubDer: Buffer } {
  const existing = loadIdentity(cfg, deviceId);
  if (existing) return existing;
  return generateIdentity(cfg, deviceId);
}

function buildIdentitySigPayload(meta: {
  device_id: string;
  peer_pub: string;
  peer_key_id: string;
  sig_ts: string;
  sig_nonce: string;
}): Buffer {
  const parts = [
    'v=1',
    `device=${meta.device_id || ''}`,
    `peer_pub=${meta.peer_pub || ''}`,
    `peer_key_id=${meta.peer_key_id || ''}`,
    `ts=${meta.sig_ts || ''}`,
    `nonce=${meta.sig_nonce || ''}`,
  ];
  return Buffer.from(`ocid|${parts.join('|')}`, 'utf-8');
}

function envelopeDigest(envelope: Record<string, any>): string {
  const canonical = [
    envelope?.magic ?? '',
    envelope?.version ?? '',
    envelope?.alg ?? '',
    envelope?.key_id ?? '',
    envelope?.nonce_b64 ?? '',
    envelope?.ek_b64 ?? '',
    envelope?.ct_b64 ?? '',
    envelope?.aad_b64 ?? '',
    envelope?.session_id ?? '',
    envelope?.enc_version ?? '',
  ];
  return crypto.createHash('sha256').update(JSON.stringify(canonical)).digest('hex');
}

function buildCommandIdentitySigPayload(meta: {
  device_id: string;
  peer_pub: string;
  peer_key_id: string;
  command_id: string;
  canonical_aad: Buffer;
  envelope: Record<string, any>;
  sig_ts: string;
  sig_nonce: string;
}): Buffer {
  const parts = [
    'v=1',
    `device=${meta.device_id || ''}`,
    `peer_pub=${meta.peer_pub || ''}`,
    `peer_key_id=${meta.peer_key_id || ''}`,
    `cmd=${meta.command_id || ''}`,
    `aad_b64=${b64e(meta.canonical_aad)}`,
    `envelope_sha256=${envelopeDigest(meta.envelope)}`,
    `ts=${meta.sig_ts || ''}`,
    `nonce=${meta.sig_nonce || ''}`,
  ];
  return Buffer.from(`occmd|${parts.join('|')}`, 'utf-8');
}

function resolveTrustPath(cfg: any, deviceId: string): string {
  if (cfg?.TRUST_PATH) return cfg.TRUST_PATH;
  const base = path.join(os.homedir(), '.openclaw');
  return path.join(base, `xiotbox_trust_${deviceId}.json`);
}

function isTruthy(value: any): boolean {
  return ['1', 'true', 'yes', 'on'].includes(String(value ?? '').toLowerCase());
}

function loadTrust(cfg: any, deviceId: string): Record<string, any> | null {
  const trustPath = resolveTrustPath(cfg, deviceId);
  if (!fs.existsSync(trustPath)) return null;
  try {
    const raw = JSON.parse(fs.readFileSync(trustPath, 'utf-8'));
    if (!raw || typeof raw !== 'object') return null;
    return raw;
  } catch (_err) {
    return null;
  }
}

function saveTrust(cfg: any, deviceId: string, data: Record<string, any>) {
  const trustPath = resolveTrustPath(cfg, deviceId);
  const dir = path.dirname(trustPath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(trustPath, JSON.stringify(data));
  try {
    fs.chmodSync(trustPath, 0o600);
  } catch (_err) {
    // best effort
  }
}

function extractClientIdentity(result: any): {
  pubDerB64: string;
  fingerprint: string;
  sigB64: string;
  sigAlg: string;
  sigTs: string;
  sigNonce: string;
} {
  return {
    pubDerB64: result?.client_identity_public_key || result?.identity_pub || '',
    fingerprint: result?.client_identity_fingerprint || result?.identity_fingerprint || '',
    sigB64: result?.client_identity_sig || result?.identity_sig || '',
    sigAlg: result?.client_identity_sig_alg || result?.identity_sig_alg || 'ed25519',
    sigTs: String(result?.client_identity_sig_ts || result?.identity_sig_ts || ''),
    sigNonce: String(result?.client_identity_sig_nonce || result?.identity_sig_nonce || ''),
  };
}

function verifyAndPinClientIdentity(
  cfg: any,
  deviceId: string,
  result: any,
  log?: any,
  command?: { commandId: string; canonicalAad: Buffer; envelope: Record<string, any> },
): { ok: boolean; fp: string; err: string } {
  const clientPub = String(result?.client_public_key || '');
  const clientKeyId = String(result?.client_key_id || '');
  if (!clientPub) return { ok: false, fp: '', err: 'e2e_peer_missing' };

  const identity = extractClientIdentity(result);
  const sigB64 = command
    ? String(result?.client_command_identity_sig || result?.command_identity_sig || '')
    : identity.sigB64;
  const sigAlg = command
    ? String(result?.client_command_identity_sig_alg || result?.command_identity_sig_alg || 'ed25519')
    : identity.sigAlg;
  const sigTs = command
    ? String(result?.client_command_identity_sig_ts || result?.command_identity_sig_ts || '')
    : identity.sigTs;
  const sigNonce = command
    ? String(result?.client_command_identity_sig_nonce || result?.command_identity_sig_nonce || '')
    : identity.sigNonce;
  if (!identity.pubDerB64 || !sigB64) return { ok: false, fp: '', err: 'client_identity_missing' };
  const alg = String(sigAlg || 'ed25519').toLowerCase().trim();
  if (alg && alg !== 'ed25519') return { ok: false, fp: '', err: 'client_identity_unsupported_alg' };

  let pubDer: Buffer;
  let sig: Buffer;
  try {
    pubDer = b64d(identity.pubDerB64);
    sig = b64d(sigB64);
  } catch (_err) {
    return { ok: false, fp: '', err: 'client_identity_invalid' };
  }
  if (!pubDer.length || !sig.length) return { ok: false, fp: '', err: 'client_identity_invalid' };

  const fp = computeFingerprintFull(pubDer);
  const claimedFp = String(identity.fingerprint || '').trim().toLowerCase();
  if (claimedFp && claimedFp !== fp) {
    // Material parses but the authenticity claim does not hold:
    // runtime-local security policy rejection (XIOT-BUG-0050b, §4.5 row 3).
    return { ok: false, fp, err: 'signature_invalid' };
  }
  const sigPayload = command
    ? buildCommandIdentitySigPayload({
        device_id: deviceId,
        peer_pub: clientPub,
        peer_key_id: clientKeyId,
        command_id: command.commandId,
        canonical_aad: command.canonicalAad,
        envelope: command.envelope,
        sig_ts: sigTs,
        sig_nonce: sigNonce,
      })
    : buildIdentitySigPayload({
        device_id: deviceId,
        peer_pub: clientPub,
        peer_key_id: clientKeyId,
        sig_ts: sigTs,
        sig_nonce: sigNonce,
      });

  try {
    const pubKey = crypto.createPublicKey({ key: pubDer, format: 'der', type: 'spki' });
    const ok = crypto.verify(null, sigPayload, pubKey, sig);
    // Structure was legal but verification failed: policy rejection, not a
    // protocol error (XIOT-BUG-0050b, PLAN-0008 §4.5 row 3).
    if (!ok) return { ok: false, fp, err: 'signature_invalid' };
  } catch (_err) {
    return { ok: false, fp, err: 'signature_invalid' };
  }

  const now = Date.now();
  const trust = loadTrust(cfg, deviceId) || { v: 2 };
  const identities: Record<
    string,
    {
      pub_der_b64: string;
      added_at: number;
      last_seen_at: number;
      client_pub_b64?: string;
      client_key_id?: string;
      peer_seen_at?: number;
    }
  > = {};
  const existingSet = trust?.client_identities;
  if (existingSet && typeof existingSet === 'object') {
    for (const [k, v] of Object.entries(existingSet)) {
      if (!k || !v || typeof v !== 'object') continue;
      identities[k] = {
        pub_der_b64: String((v as any).pub_der_b64 || ''),
        added_at: Number((v as any).added_at || now),
        last_seen_at: Number((v as any).last_seen_at || now),
        client_pub_b64: String((v as any).client_pub_b64 || ''),
        client_key_id: String((v as any).client_key_id || ''),
        peer_seen_at: Number((v as any).peer_seen_at || 0),
      };
    }
  }

  // Backward compatibility: migrate legacy single-pin shape into set.
  const legacyFp = String(trust?.client_identity_fingerprint || '').trim().toLowerCase();
  const legacyPub = String(trust?.client_identity_public_key || '').trim();
  if (legacyFp && legacyPub && !identities[legacyFp]) {
    identities[legacyFp] = {
      pub_der_b64: legacyPub,
      added_at: Number(trust?.updated_at || now),
      last_seen_at: Number(trust?.updated_at || now),
    };
  }

  const allowNew = isTruthy(cfg?.ALLOW_NEW_CLIENT_IDENTITIES);
  const knownKeys = Object.keys(identities);
  if (knownKeys.length === 0) {
    identities[fp] = {
      pub_der_b64: identity.pubDerB64,
      added_at: now,
      last_seen_at: now,
      client_pub_b64: clientPub,
      client_key_id: clientKeyId,
      peer_seen_at: now,
    };
    saveTrust(cfg, deviceId, {
      v: 2,
      client_identities: identities,
      updated_at: now,
    });
    log?.info?.(`[XiotBox] Pinned initial client identity fingerprint: ${fp.slice(0, 12)}...`);
    return { ok: true, fp, err: '' };
  }

  const known = identities[fp];
  if (known) {
    known.last_seen_at = now;
    if (!known.pub_der_b64) {
      known.pub_der_b64 = identity.pubDerB64;
    }
    known.client_pub_b64 = clientPub;
    known.client_key_id = clientKeyId;
    known.peer_seen_at = now;
    saveTrust(cfg, deviceId, {
      v: 2,
      client_identities: identities,
      updated_at: now,
    });
    return { ok: true, fp, err: '' };
  }

  if (allowNew) {
    identities[fp] = {
      pub_der_b64: identity.pubDerB64,
      added_at: now,
      last_seen_at: now,
      client_pub_b64: clientPub,
      client_key_id: clientKeyId,
      peer_seen_at: now,
    };
    saveTrust(cfg, deviceId, {
      v: 2,
      client_identities: identities,
      updated_at: now,
    });
    log?.warn?.(`[XiotBox] Enrolled additional client identity fingerprint: ${fp.slice(0, 12)}...`);
    return { ok: true, fp, err: '' };
  }

  log?.error?.(
    `[XiotBox] Client identity changed (known=${knownKeys.map((x) => x.slice(0, 12)).join(',')} got=${fp.slice(0, 12)}...)`,
  );
  return { ok: false, fp, err: 'client_identity_changed' };
}

function loadTrustedClientPeers(cfg: any, deviceId: string): Array<{ publicKey: string; keyId: string }> {
  const trust = loadTrust(cfg, deviceId) || {};
  const peers: Array<{ publicKey: string; keyId: string }> = [];
  const seen = new Set<string>();
  const identities = trust?.client_identities;
  if (!identities || typeof identities !== 'object') return peers;
  for (const v of Object.values(identities)) {
    if (!v || typeof v !== 'object') continue;
    const pub = String((v as any).client_pub_b64 || '').trim();
    if (!pub) continue;
    const raw = decodePubkey(pub);
    if (!raw || raw.length !== PUBKEY_LEN) continue;
    const keyId = String((v as any).client_key_id || '').trim() || computeKeyId(raw);
    const dedupeKey = `${keyId}|${b64e(raw)}`;
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);
    peers.push({ publicKey: b64e(raw), keyId });
  }
  return peers;
}

function loadKeypair(cfg: any, deviceId: string): { priv: Buffer; pub: Buffer; keyId: string } | null {
  const keyPath = resolveKeyPath(cfg, deviceId);
  if (!fs.existsSync(keyPath)) return null;
  try {
    const raw = JSON.parse(fs.readFileSync(keyPath, 'utf-8'));
    const privRaw = b64d(raw.priv_b64 || '');
    const pubRaw = b64d(raw.pub_b64 || '');
    if (privRaw.length !== 32 || pubRaw.length !== 32) return null;
    return { priv: privRaw, pub: pubRaw, keyId: raw.key_id || computeKeyId(pubRaw) };
  } catch (_err) {
    return null;
  }
}

function saveKeypair(cfg: any, deviceId: string, priv: Buffer, pub: Buffer): { priv: Buffer; pub: Buffer; keyId: string } {
  const keyPath = resolveKeyPath(cfg, deviceId);
  const dir = path.dirname(keyPath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const keyId = computeKeyId(pub);
  const payload = {
    v: 1,
    alg: E2E_KEY_ALG,
    priv_b64: b64e(priv),
    pub_b64: b64e(pub),
    key_id: keyId,
  };
  fs.writeFileSync(keyPath, JSON.stringify(payload));
  try {
    fs.chmodSync(keyPath, 0o600);
  } catch (_err) {
    // best effort
  }
  return { priv, pub, keyId };
}

function generateKeypair(cfg: any, deviceId: string): { priv: Buffer; pub: Buffer; keyId: string } {
  const { priv, pub } = x25519Keypair();
  return saveKeypair(cfg, deviceId, priv, pub);
}

async function postJsonRpc(url: string, params: Record<string, any>, headers: Record<string, string>): Promise<any> {
  const body = JSON.stringify({ jsonrpc: '2.0', method: 'call', params });
  if (typeof fetch === 'function') {
    const resp = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...headers,
      },
      body,
    });
    const data = await resp.json().catch(() => null);
    if (!data) throw new Error('invalid_response');
    if (data.error) throw new Error(data.error?.data?.message || data.error?.message || 'rpc_error');
    return data.result;
  }
  return await new Promise((resolve, reject) => {
    const u = new URL(url);
    const lib = u.protocol === 'https:' ? https : http;
    const req = lib.request(
      {
        method: 'POST',
        hostname: u.hostname,
        port: u.port || (u.protocol === 'https:' ? 443 : 80),
        path: u.pathname + u.search,
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body),
          ...headers,
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
        res.on('end', () => {
          try {
            const text = Buffer.concat(chunks).toString('utf-8');
            const data = JSON.parse(text);
            if (data.error) {
              reject(new Error(data.error?.data?.message || data.error?.message || 'rpc_error'));
              return;
            }
            resolve(data.result);
          } catch (err) {
            reject(err);
          }
        });
      },
    );
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

export class OpenClawE2E {
  cfg: any;
  log: any;
  privRaw: Buffer | null = null;
  pubRaw: Buffer | null = null;
  keyId: string = '';
  identityPrivKey: crypto.KeyObject | null = null;
  identityPubDer: Buffer | null = null;
  identityFingerprint: string = '';
  peerPublicKey: string = '';
  peerKeyId: string = '';
  peerTrustError: string = '';
  threadId: string = DEFAULT_THREAD_ID;
  encV: number = E2E_VERSION;
  clientPeerKeys: Array<{ client_key_id: string; client_public_key: string }> = [];

  constructor(cfg: any, log?: any) {
    this.cfg = cfg || {};
    this.log = log;
  }

  init() {
    const existing = loadKeypair(this.cfg, this.cfg.DEVICE_ID);
    const rotateFlag = String(this.cfg.E2E_ROTATE || '').toLowerCase();
    const rotate = ['1', 'true', 'yes', 'on'].includes(rotateFlag);
    const keypair = rotate || !existing ? generateKeypair(this.cfg, this.cfg.DEVICE_ID) : existing;
    this.privRaw = keypair.priv;
    this.pubRaw = keypair.pub;
    this.keyId = keypair.keyId;
    try {
      const identity = ensureIdentity(this.cfg, this.cfg.DEVICE_ID);
      this.identityPrivKey = crypto.createPrivateKey({ key: identity.privDer, format: 'der', type: 'pkcs8' });
      this.identityPubDer = identity.pubDer;
      this.identityFingerprint = computeFingerprintFull(identity.pubDer);
    } catch (err: any) {
      this.identityPrivKey = null;
      this.identityPubDer = null;
      this.identityFingerprint = '';
      this.log?.warn?.(`[XiotBox] Identity key init failed: ${err?.message || err}`);
    }
    if (this.log?.info) {
      const backend = HAS_NATIVE_X25519 ? 'native' : 'noble';
      this.log.info(`[XiotBox] E2E x25519 backend: ${backend}`);
    }
  }

  async refreshPeerKey() {
    const apiBase = this.cfg.API_BASE_URL || this._deriveApiBase();
    if (!apiBase) throw new Error('missing_api_base');
    const url = `${apiBase.replace(/\/$/, '')}/agent/devices/e2e/peer_key`;
    const headers = {
      Authorization: `Bearer ${this.cfg.DEVICE_TOKEN}`,
      'X-Device-Id': this.cfg.DEVICE_ID,
    };
    // Register the same signed E2E identity claim used by HELLO. The Lite
    // peer-key endpoint is the authoritative persistence seam consumed by
    // MCP/client senders; registering only X25519 here leaves the peer
    // identity empty and causes strict senders to fail closed.
    const payload: Record<string, any> = this.helloPayload() || {};
    let result;
    try {
      result = await postJsonRpc(url, payload, headers);
    } catch (err: any) {
      if (!this.cfg.API_BASE_URL) {
        throw new Error('missing_api_base');
      }
      throw err;
    }
    const clientPub = result?.client_public_key || '';
    const clientKeyId = result?.client_key_id || '';
    if (clientPub) {
      const verified = verifyAndPinClientIdentity(this.cfg, this.cfg.DEVICE_ID, result, this.log);
      if (!verified.ok) {
        this.peerPublicKey = '';
        this.peerKeyId = '';
        this.peerTrustError = verified.err || 'client_identity_invalid';
        throw new Error(this.peerTrustError);
      }
      this.peerPublicKey = clientPub;
      this.peerKeyId = clientKeyId;
      this.peerTrustError = '';
    } else {
      this.peerPublicKey = '';
      this.peerKeyId = '';
      this.peerTrustError = 'e2e_peer_missing';
    }
    this.threadId = normalizeThreadId(result?.thread_id);
    this.encV = result?.enc_v || E2E_VERSION;
    // Store client_peer_keys from server
    if (Array.isArray(result?.client_peer_keys)) {
      this.clientPeerKeys = result.client_peer_keys;
    }
    return result;
  }

  helloPayload() {
    if (!this.pubRaw) return null;
    const peerPub = b64e(this.pubRaw);
    const peerKeyId = this.keyId || computeKeyId(this.pubRaw);
    const payload: Record<string, any> = {
      pubkey: peerPub,
      key_id: peerKeyId,
      algo: E2E_KEY_ALG,
      enc_v: this.encV || E2E_VERSION,
      fingerprint: computeFingerprint(this.pubRaw),
    };
    if (this.identityPrivKey && this.identityPubDer) {
      const sigTs = String(Date.now());
      const sigNonce = crypto.randomBytes(16).toString('hex');
      const sigPayload = buildIdentitySigPayload({
        device_id: this.cfg.DEVICE_ID,
        peer_pub: peerPub,
        peer_key_id: peerKeyId,
        sig_ts: sigTs,
        sig_nonce: sigNonce,
      });
      try {
        const sig = crypto.sign(null, sigPayload, this.identityPrivKey);
        payload.identity_pub = b64e(this.identityPubDer);
        payload.identity_fingerprint = this.identityFingerprint || computeFingerprintFull(this.identityPubDer);
        payload.identity_sig = b64e(sig);
        payload.identity_sig_alg = 'ed25519';
        payload.identity_sig_ts = sigTs;
        payload.identity_sig_nonce = sigNonce;
      } catch (err: any) {
        this.log?.warn?.(`[XiotBox] Identity signature failed: ${err?.message || err}`);
      }
    }
    return payload;
  }

  buildAad(meta: {
    direction: string;
    device_id: string;
    thread_id: string;
    command_id: string;
    content_type: string;
    chunk_seq?: number;
    enc_v?: number;
    /**
     * Optional trailing `|preset=<value>` AAD segment (XIOT-BUG-0118): bound
     * IFF the dispatch carries a non-empty permission_preset. Absent/empty
     * is canonical for "no preset" and yields byte-identical legacy AAD; an
     * empty segment is never serialized. Receivers derive it from THIS
     * dispatch frame's payload field, so a preset replaced, deleted or
     * added in flight fails AAD verification with its ciphertext.
     */
    permission_preset?: string | null;
  }): Buffer {
    const encV = meta.enc_v || this.encV || E2E_VERSION;
    const parts = [
      `v=${encV}`,
      `dir=${meta.direction || ''}`,
      `device=${meta.device_id || ''}`,
      `thread=${normalizeThreadId(meta.thread_id || this.threadId)}`,
      `cmd=${meta.command_id || ''}`,
      `type=${meta.content_type || ''}`,
      `seq=${meta.chunk_seq || 0}`,
    ];
    const preset = String(meta.permission_preset ?? '').trim();
    if (preset) parts.push(`preset=${preset}`);
    return Buffer.from(`oc|${parts.join('|')}`, 'utf-8');
  }

  ensurePeerKey() {
    const raw = decodePubkey(this.peerPublicKey || '');
    if (!raw) throw new Error('missing_peer_key');
    return raw;
  }

  resolveCommandPeerFromPayload(
    payload: any,
    command: { commandId: string; canonicalAad: Buffer; envelope: Record<string, any> },
  ): { publicKey: string; keyId: string } | null {
    this.peerTrustError = '';
    if (!payload || typeof payload !== 'object') {
      this.peerTrustError = 'e2e_peer_missing';
      return null;
    }
    const clientPub = String(payload?.client_public_key || payload?.client_pubkey || '').trim();
    if (!clientPub) {
      this.peerTrustError = 'e2e_peer_missing';
      return null;
    }
    const clientRaw = decodePubkey(clientPub);
    if (!clientRaw || clientRaw.length !== PUBKEY_LEN) {
      this.peerTrustError = 'e2e_peer_missing';
      return null;
    }
    const clientKeyId = String(payload?.client_key_id || '').trim() || computeKeyId(clientRaw);
    const verified = verifyAndPinClientIdentity(
      this.cfg,
      this.cfg.DEVICE_ID,
      {
        client_public_key: b64e(clientRaw),
        client_key_id: clientKeyId,
        client_identity_public_key:
          payload?.client_identity_public_key || payload?.identity_pub || payload?.client_identity_pub || '',
        client_identity_fingerprint:
          payload?.client_identity_fingerprint || payload?.identity_fingerprint || '',
        client_identity_sig: payload?.client_identity_sig || payload?.identity_sig || '',
        client_identity_sig_alg: payload?.client_identity_sig_alg || payload?.identity_sig_alg || '',
        client_identity_sig_ts: payload?.client_identity_sig_ts || payload?.identity_sig_ts || '',
        client_identity_sig_nonce: payload?.client_identity_sig_nonce || payload?.identity_sig_nonce || '',
        client_command_identity_sig: payload?.client_command_identity_sig || payload?.command_identity_sig || '',
        client_command_identity_sig_alg:
          payload?.client_command_identity_sig_alg || payload?.command_identity_sig_alg || '',
        client_command_identity_sig_ts:
          payload?.client_command_identity_sig_ts || payload?.command_identity_sig_ts || '',
        client_command_identity_sig_nonce:
          payload?.client_command_identity_sig_nonce || payload?.command_identity_sig_nonce || '',
      },
      this.log,
      command,
    );
    if (!verified.ok) {
      this.peerTrustError = verified.err || 'client_identity_invalid';
      this.log?.warn?.(
        `[XiotBox] Command peer identity rejected err=${verified.err || 'client_identity_invalid'} key=${clientKeyId.slice(0, 8)}...`,
      );
      return null;
    }
    this.peerTrustError = '';
    return { publicKey: b64e(clientRaw), keyId: clientKeyId };
  }

  collectReplyPeers(
    payload: any,
    command: { commandId: string; canonicalAad: Buffer; envelope: Record<string, any> },
  ): Array<{ publicKey: string; keyId: string }> {
    const primary = this.resolveCommandPeerFromPayload(payload, command);
    if (!primary) {
      if (!this.peerTrustError) {
        this.peerTrustError = 'e2e_peer_missing';
      }
      return [];
    }

    const peers: Array<{ publicKey: string; keyId: string }> = [];
    const seen = new Set<string>();
    const pushPeer = (peer: { publicKey: string; keyId: string } | null) => {
      if (!peer) return;
      const raw = decodePubkey(peer.publicKey || '');
      if (!raw || raw.length !== PUBKEY_LEN) return;
      const keyId = String(peer.keyId || '').trim() || computeKeyId(raw);
      const pubB64 = b64e(raw);
      const dedupeKey = `${keyId}|${pubB64}`;
      if (seen.has(dedupeKey)) return;
      seen.add(dedupeKey);
      peers.push({ publicKey: pubB64, keyId });
    };

    // Keep request sender as first/primary recipient for deterministic routing.
    pushPeer(primary);
    if (this.peerPublicKey) {
      pushPeer({ publicKey: this.peerPublicKey, keyId: this.peerKeyId || '' });
    }
    // Include stored client_peer_keys from server
    if (Array.isArray(this.clientPeerKeys)) {
      for (const item of this.clientPeerKeys) {
        if (!item || typeof item !== 'object') continue;
        const pub = String(item.client_public_key || '').trim();
        const keyId = String(item.client_key_id || '').trim();
        if (!pub) continue;
        pushPeer({ publicKey: pub, keyId });
      }
    }
    const advertisedPeers = payload?.client_peer_keys || payload?.client_peers;
    if (Array.isArray(advertisedPeers)) {
      for (const item of advertisedPeers) {
        if (!item || typeof item !== 'object') continue;
        const pub = String(
          (item as any).client_public_key ||
            (item as any).public_key ||
            (item as any).pubkey ||
            (item as any).peer_public_key ||
            '',
        ).trim();
        const keyId = String(
          (item as any).client_key_id || (item as any).key_id || (item as any).peer_key_id || '',
        ).trim();
        if (!pub) continue;
        pushPeer({ publicKey: pub, keyId });
      }
    }
    for (const peer of loadTrustedClientPeers(this.cfg, this.cfg.DEVICE_ID)) {
      pushPeer(peer);
    }
    return peers;
  }

  directReplyPeers(): Array<{ publicKey: string; keyId: string }> {
    // Peer set for a channel-originated direct message (subagent announce,
    // approval followup) that has no inbound command envelope.  Reuses the
    // same primaries as collectReplyPeers minus the command-sender peer.
    const peers: Array<{ publicKey: string; keyId: string }> = [];
    const seen = new Set<string>();
    const pushPeer = (peer: { publicKey: string; keyId: string } | null) => {
      if (!peer) return;
      const raw = decodePubkey(peer.publicKey || '');
      if (!raw || raw.length !== PUBKEY_LEN) return;
      const keyId = String(peer.keyId || '').trim() || computeKeyId(raw);
      const pubB64 = b64e(raw);
      const dedupeKey = `${keyId}|${pubB64}`;
      if (seen.has(dedupeKey)) return;
      seen.add(dedupeKey);
      peers.push({ publicKey: pubB64, keyId });
    };
    if (this.peerPublicKey) pushPeer({ publicKey: this.peerPublicKey, keyId: this.peerKeyId });
    for (const item of this.clientPeerKeys) {
      pushPeer({ publicKey: item.client_public_key, keyId: item.client_key_id });
    }
    for (const peer of loadTrustedClientPeers(this.cfg, this.cfg.DEVICE_ID)) {
      pushPeer(peer);
    }
    return peers;
  }

  encryptText(text: string, meta: any, peer?: { publicKey?: string; keyId?: string }) {
    if (!this.pubRaw || !this.privRaw) throw new Error('missing_keypair');
    const peerRaw = peer?.publicKey ? decodePubkey(peer.publicKey) : this.ensurePeerKey();
    if (!peerRaw) throw new Error('missing_peer_key');

    // Use enc_version=2 for v2 protocol
    const encVersion = 2;
    const metaWithEncV = { ...meta, enc_v: encVersion };
    const aad = this.buildAad(metaWithEncV);
    const keyId = String(peer?.keyId || this.peerKeyId || '').trim() || computeKeyId(peerRaw);

    // Generate session_id
    const sessionId = crypto.randomUUID();

    return buildEnvelope(Buffer.from(text || '', 'utf-8'), peerRaw, keyId || '', aad, sessionId, encVersion);
  }

  decryptText(envelope: Record<string, any>, meta: any): string {
    if (!this.privRaw) throw new Error('missing_keypair');

    // Read enc_version for controlled fallback
    const encVersion = envelope.enc_version ?? 1;

    // Priority 1: canonical AAD derived from THIS frame's metadata (never
    // the envelope-carried AAD — since XIOT-BUG-0118 decryptEnvelope rejects
    // a v2 mismatch, trusting packetAAD here would bypass canonical
    // verification of the authenticated dispatch context).
    const localAad = this.buildAad(meta);
    try {
      const raw = decryptEnvelope(envelope, this.privRaw, localAad);
      return raw.toString('utf-8');
    } catch (err) {
      console.warn('[E2E] Decrypt with canonical localAAD failed, trying packetAAD', {
        error: err instanceof Error ? err.message : String(err),
      });
    }

    // Priority 2: packetAAD (envelope.aad_b64) — legacy envelopes only.
    const envAad = envelope.aad_b64 ? b64d(envelope.aad_b64) : null;
    if (envAad && (envelope.enc_version ?? 1) < 2) {
      try {
        const raw = decryptEnvelope(envelope, this.privRaw, envAad);
        return raw.toString('utf-8');
      } catch (err) {
        console.warn('[E2E] Decrypt with packetAAD failed', {
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }
    try {
      const raw = decryptEnvelope(envelope, this.privRaw, localAad);
      return raw.toString('utf-8');
    } catch (err) {
      // Priority 3: Legacy fallbacks (only for v0/v1)
      if (encVersion < 2) {
        console.warn('[E2E] Canonical localAAD failed, trying legacy fallbacks (enc_v < 2)');
        // Try with empty AAD for v0
        if (encVersion === 0) {
          try {
            const raw = decryptEnvelope(envelope, this.privRaw, null);
            return raw.toString('utf-8');
          } catch (legacyErr) {
            // Fall through to throw original error
          }
        }
      }
      throw err;
    }
  }

  _deriveApiBase(): string {
    const wssUrl = this.cfg.GATEWAY_WSS_URL;
    if (!wssUrl) return '';
    try {
      const u = new URL(wssUrl);
      const scheme = u.protocol === 'wss:' ? 'https:' : 'http:';
      return `${scheme}//${u.host}`;
    } catch (_err) {
      return '';
    }
  }
}
