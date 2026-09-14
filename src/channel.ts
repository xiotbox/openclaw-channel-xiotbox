import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import WSSClient from '../wss_client.js';
import { getXiotboxRuntimeOrNull } from './runtime.js';
import type { RuntimeReplySurface } from './runtime.js';
import { OpenClawE2E } from './e2e.js';
import {
  handleGatewayApprovalResolve,
  handleOutboundApprovalPayload,
  registerActiveApprovalBinding,
  registerApprovalLifecycleAccount,
  xiotboxApprovalCapability,
} from './approval-lifecycle.js';
import {
  handleGatewayAskUserResolve,
  handleOutboundAskUserPayload,
  registerActiveAskUserBinding,
  registerAskUserLifecycleAccount,
} from './ask-user-lifecycle.js';
import { handleAgentProfileSync } from './agent-profile-sync.js';
import { CommandLifecycleEmitter, normalizeRuntimeError } from './command-ack.js';
import { DurableEventOutbox, resolveEventOutboxPath } from './event-outbox.js';
import {
  projectAssistantMessage,
  projectUserMessage,
} from './conversation-projection.js';
import {
  registerActiveMemoryBinding,
  registerMemoryLifecycleAccount,
} from './memory-lifecycle.js';
import {
  registerActiveSubagentParent,
  registerSubagentLifecycleAccount,
  resolvePendingSubagentDeliveryByConversation,
} from './subagent-lifecycle.js';
import { registerActiveToolRun, setSessionPermission } from './tool-lifecycle.js';
import { setSessionModelOverride } from './session-model.js';
import {
  OPENCLAW_RUNTIME_KIND,
  buildOpenclawCapabilityDeclaration,
  buildOpenclawResourceFacts,
} from './runtime-profile.js';
import { executeWorkspaceControl } from './workspace-control.js';
import {
  buildOpenclawWorkspaceRegistry,
  openclawWorkspaceAvailable,
} from './runtime-workspace.js';
import { getDirectSender, registerDirectSender } from './direct-send.js';
import {
  clearConnectedAt,
  describeGatewayAccountState,
  getGatewayAccount,
  nextGatewayInstanceId,
  registerGatewayAccount,
  removeGatewayAccount,
  setConnectedAt,
  stopGatewayAccount,
} from './gateway-state.js';
import {
  buildConfig,
  buildSessionKey,
  CHANNEL_ID,
  getChannelConfig,
  listAccountIds,
  normalizeAccountId,
  normalizeAgentId,
  normalizeContextEpoch,
  normalizePositiveInt,
  normalizeStringValue,
  normalizeStrList,
  normalizeThreadId,
  resolveAccount,
  resolveAgentId,
  resolveDefaultAccountId,
  resolveConversationBinding,
  resolveEffectiveConfig,
  resolveThreadAgentId,
} from './config.js';

const SESSION_STORE_CACHE_TTL_MS = 3000;
const CONTEXT_EPOCH_CACHE_TTL_MS = 24 * 60 * 60 * 1000;
const CONTEXT_EPOCH_CACHE_MAX = 2000;

type SessionUsageSnapshot = {
  totalTokens: number;
  inputTokens?: number;
  outputTokens?: number;
  contextTokens?: number;
  totalTokensFresh?: boolean;
  updatedAt?: number;
};

type SessionStoreCache = {
  storePath: string;
  mtimeMs: number;
  loadedAt: number;
  store: Record<string, any>;
};

type ContextEpochCacheEntry = {
  epoch: number;
  updatedAt: number;
};

type InboundMediaEntry = {
  path?: string;
  url?: string;
  type?: string;
};

type InboundMediaContextFields = {
  MediaPath?: string;
  MediaUrl?: string;
  MediaType?: string;
  MediaPaths?: string[];
  MediaUrls?: string[];
  MediaTypes?: string[];
};

type ProgressSnapshot = {
  status?: string;
  stage?: string;
  detail?: string;
  progressPercent?: number;
};

type StreamEvent = Record<string, any>;

type GatewayLogSink = {
  debug?: (message: string) => void;
  info?: (message: string) => void;
  warn?: (message: string) => void;
  error?: (message: string) => void;
};

type GatewayContextLike = {
  accountId?: string | null;
  cfg?: unknown;
  channelRuntime?: {
    reply?: RuntimeReplySurface;
  } | null;
  getStatus?: () => Record<string, unknown>;
  setStatus?: (status: Record<string, unknown>) => void;
};

type GatewayStartContextLike = GatewayContextLike & {
  log?: GatewayLogSink;
  abortSignal?: AbortSignal;
};

let sessionStoreCache: SessionStoreCache | null = null;
const contextEpochCache = new Map<string, ContextEpochCacheEntry>();

function getChannelRuntimeSurface(ctx: GatewayContextLike): GatewayContextLike['channelRuntime'] | null {
  return ctx?.channelRuntime || null;
}

function getReplyApi(ctx: GatewayContextLike): RuntimeReplySurface | null {
  const channelRuntime = getChannelRuntimeSurface(ctx);
  return channelRuntime?.reply || getXiotboxRuntimeOrNull()?.channel?.reply || null;
}

function updateGatewayStatus(
  ctx: GatewayContextLike,
  accountId: string,
  patch: Record<string, unknown>,
  log?: GatewayLogSink,
): void {
  if (typeof ctx?.setStatus !== 'function') return;
  try {
    const current = typeof ctx.getStatus === 'function' ? ctx.getStatus() : {};
    ctx.setStatus({
      ...current,
      accountId,
      ...patch,
    });
  } catch (err) {
    // Status reporting must never break the channel connection path.
    log?.warn?.(`[XiotBox][${accountId}] status update failed: ${err instanceof Error ? err.message : String(err)}`);
  }
}

function hasOwn(obj: any, key: string): boolean {
  return Boolean(obj && typeof obj === 'object' && Object.prototype.hasOwnProperty.call(obj, key));
}

function contextEpochScopeKey(deviceId: string, threadId: string): string {
  return `${deviceId}:${normalizeThreadId(threadId)}`;
}

function pruneContextEpochCache(): void {
  const now = Date.now();
  for (const [key, entry] of contextEpochCache.entries()) {
    if (now - entry.updatedAt > CONTEXT_EPOCH_CACHE_TTL_MS) {
      contextEpochCache.delete(key);
    }
  }
  if (contextEpochCache.size <= CONTEXT_EPOCH_CACHE_MAX) return;
  const overflow = contextEpochCache.size - CONTEXT_EPOCH_CACHE_MAX;
  const oldest = [...contextEpochCache.entries()].sort((a, b) => a[1].updatedAt - b[1].updatedAt);
  for (let i = 0; i < overflow; i += 1) {
    const candidate = oldest[i];
    if (!candidate) break;
    contextEpochCache.delete(candidate[0]);
  }
}

// ── Session command dispatch (XIOT-BUG-0006) ──
// The gateway forwards command_type in the bot COMMAND payload
// (client_ws.py flattens it next to command_id). Non-chat session commands
// carry plain JSON and no OGE2E1 envelope; routing them into the chat path
// used to fail with e2e_required. Chat stays the default action.

export type SessionCommandAction =
  | 'chat'
  | 'model_select'
  | 'archive'
  | 'interrupt'
  | 'unsupported';

export function resolveSessionCommandAction(commandType: unknown): SessionCommandAction {
  const normalized = String(commandType || '').trim();
  switch (normalized) {
    case '':
    case 'chat':
      return 'chat';
    case 'session.model.select':
      return 'model_select';
    case 'session.archive':
      return 'archive';
    case 'session.interrupt':
      return 'interrupt';
    default:
      return 'unsupported';
  }
}

// conversation_id → last seen chat binding. session.* commands carry only
// conversation_id, so this registry maps them back onto the exact OpenClaw
// session the conversation is bound to. In-memory on purpose: after a plugin
// restart the next chat message re-registers it, and a miss fails the command
// instead of overriding the wrong session.
type KnownConversationBinding = {
  sessionKey: string;
  agentId: string;
  contextEpoch: number;
  ts: number;
};
const CONVERSATION_BINDING_TTL_MS = 24 * 60 * 60 * 1000;
const CONVERSATION_BINDING_MAX = 500;
const conversationBindingRegistry = new Map<string, KnownConversationBinding>();

export function rememberConversationBinding(
  conversationId: string,
  binding: { sessionKey: string; agentId: string; contextEpoch: number },
): void {
  const key = String(conversationId || '').trim();
  if (!key) return;
  const now = Date.now();
  for (const [k, v] of conversationBindingRegistry.entries()) {
    if (now - v.ts > CONVERSATION_BINDING_TTL_MS) conversationBindingRegistry.delete(k);
  }
  while (conversationBindingRegistry.size >= CONVERSATION_BINDING_MAX) {
    const firstKey = conversationBindingRegistry.keys().next().value;
    conversationBindingRegistry.delete(firstKey);
  }
  conversationBindingRegistry.set(key, { ...binding, ts: now });
}

export function lookupConversationBinding(
  conversationId: string,
): KnownConversationBinding | null {
  const key = String(conversationId || '').trim();
  if (!key) return null;
  const entry = conversationBindingRegistry.get(key) || null;
  if (!entry) return null;
  if (Date.now() - entry.ts > CONVERSATION_BINDING_TTL_MS) {
    conversationBindingRegistry.delete(key);
    return null;
  }
  return entry;
}

// Pending SESSION.ARCHIVE round-trips keyed by conversation_id. The gateway
// replies SESSION.ARCHIVE_ACK {ok, conversation_id?, session_id?, error?};
// the pending entry settles the COMMAND_RESULT of the originating command.
type PendingSessionArchive = {
  cmdId: string;
  traceId: string | null;
  client: any;
  timer: any;
  // Terminal wiring (XIOT-BUG-0050b R1): when the archive settles, the
  // terminal COMMAND_RESULT is cached first and only then is the execution
  // ownership released — duplicates replay the cached result and can never
  // re-enter the business path.
  cacheResult?: (cmdId: string, type: string, payload: any) => void;
  lifecycle?: {
    markTerminal: (cmdId: string) => boolean;
  };
};
const SESSION_ARCHIVE_ACK_TIMEOUT_MS = 8000;
// Exported for testing.
export const pendingSessionArchives = new Map<string, PendingSessionArchive>();

// Settle a SESSION.ARCHIVE_ACK against the pending registry. The gateway
// error path echoes only session_id (not conversation_id), so fall back to
// session_id and finally to a single-pending match; unresolved acks expire
// via the pending timeout instead of blocking the client forever.
export function settleSessionArchiveAck(data: any): boolean {
  const payload = data?.payload || data || {};
  const byConversation = String(payload.conversation_id || '').trim();
  if (byConversation && pendingSessionArchives.has(byConversation)) {
    return settleSessionArchive(byConversation, payload.ok === true, payload.error);
  }
  const bySession = String(payload.session_id || '').trim();
  if (bySession && pendingSessionArchives.has(bySession)) {
    return settleSessionArchive(bySession, payload.ok === true, payload.error);
  }
  if (!byConversation && !bySession && pendingSessionArchives.size === 1) {
    const [onlyKey] = pendingSessionArchives.keys();
    return settleSessionArchive(onlyKey, payload.ok === true, payload.error);
  }
  return false;
}

function settleSessionArchive(
  conversationId: string,
  ok: boolean,
  error?: string,
): boolean {
  const key = String(conversationId || '').trim();
  const entry = pendingSessionArchives.get(key);
  if (!entry) return false;
  pendingSessionArchives.delete(key);
  if (entry.timer) clearTimeout(entry.timer);
  const terminalPayload = {
    command_id: entry.cmdId,
    status: ok ? 'success' : 'failed',
    trace_id: entry.traceId,
    ...(ok ? {} : { error: error || 'session_archive_failed' }),
    result: ok ? { conversation_id: key } : {},
  };
  entry.client.sendMessage('COMMAND_RESULT', terminalPayload);
  // Terminal ordering contract (XIOT-BUG-0050b R1): cache the terminal
  // result BEFORE releasing the execution ownership, so a duplicate that
  // arrives after release hits the cached terminal — never a re-execution
  // window.
  entry.cacheResult?.(entry.cmdId, 'COMMAND_RESULT', terminalPayload);
  entry.lifecycle?.markTerminal(entry.cmdId);
  return true;
}

// ── Canonical v1 command lifecycle for session commands (XIOT-BUG-0050b) ──
// Every v1 command answers one canonical COMMAND_ACK before any further
// processing (PLAN-0008 §4.1). Protocol/security gates that fail emit
// COMMAND_ACK {accepted:false, rejection:{class,code,detail?}} — the Gateway
// terminalizes `failed` from that ACK, so no COMMAND_RESULT is produced for
// rejections. Commands that pass all gates emit COMMAND_ACK {accepted:true}
// and then reliable COMMAND_DELIVERED at the business entry; no-turn actions
// (model.select) go delivered → completed and never fabricate message.user
// or run.* events (§4.6). Rejection classification uses the registered exact
// code table (normalizeRuntimeError, §4.5) — never string-prefix parsing.
export type SessionCommandContext = {
  client: { sendMessage: (type: string, payload: any) => void };
  lifecycle: CommandLifecycleEmitter;
  cacheResult: (cmdId: string, type: string, payload: any) => void;
  // Optional terminal-result lookup (same store cacheResult writes). When
  // provided, duplicates of an already-completed command replay the cached
  // terminal here — including after the execution ownership was released,
  // closing any re-execution window (XIOT-BUG-0050b R1).
  cachedResult?: (cmdId: string) => { type: string; payload: any } | null;
  log?: any;
  deviceId: string;
};

export function dispatchSessionCommand(
  ctx: SessionCommandContext,
  args: {
    action: 'model_select' | 'archive' | 'interrupt' | 'unsupported';
    payload: any;
    incoming: any;
    cmdId: string;
    traceId: string | null;
  },
): void {
  const { client, lifecycle, cacheResult, cachedResult, log } = ctx;
  const { action, payload, incoming, cmdId, traceId } = args;

  // Terminal replay first (XIOT-BUG-0050b R1): a duplicate of an
  // already-completed command replays the cached terminal result — including
  // after the ownership entry was released/pruned. Together with the
  // ownership gate below this leaves no re-execution window: ownership only
  // ever releases AFTER the terminal is cached.
  const terminal = cachedResult ? cachedResult(cmdId) : null;
  if (terminal) {
    client.sendMessage(terminal.type, terminal.payload);
    return;
  }

  const rejectWith = (code: string, detail?: string) => {
    const rejection = normalizeRuntimeError(code);
    if (detail && !rejection.detail) {
      rejection.detail = String(detail).slice(0, 512);
    }
    const frame = lifecycle.ackRejected(cmdId, rejection, traceId);
    if (frame) cacheResult(cmdId, frame.type, frame);
  };

  // Per-command execution gate (XIOT-BUG-0050b R1): command_id is the sole
  // idempotency key. The first call claims execution and emits the canonical
  // accepted ACK; any duplicate (redelivery, retry, same-tick race, even with
  // different/invalid content) replays the recorded lifecycle evidence and
  // must not re-enter the business path or re-classify the command. Returns
  // false when the caller must short-circuit.
  const enterBusinessEntry = (): boolean => {
    if (!lifecycle.ackAccepted(cmdId, traceId)) return false;
    lifecycle.markDelivered(cmdId);
    return true;
  };

  if (action === 'unsupported') {
    // Profile/vocabulary mismatch (or an unregistered command word): normalized
    // to protocol/capability_mismatch so the Gateway refreshes the profile.
    rejectWith('unsupported_command_type');
    return;
  }

  if (action === 'interrupt') {
    // The OpenClaw host exposes no per-session cancel seam to channel plugins;
    // declaring interrupt=true made clients offer a button that always failed
    // with e2e_required. The profile declares interrupt=false; if a command
    // still leaks here it is normalized to protocol/capability_mismatch.
    log?.warn?.(`[XiotBox] session.interrupt unsupported on OpenClaw runtime cmd=${cmdId}`);
    rejectWith('interrupt_unavailable');
    return;
  }

  const conversationId = normalizeStringValue(
    incoming?.conversation_id ?? payload?.conversation_id,
  ) || '';
  if (!conversationId) {
    rejectWith('conversation_id_required');
    return;
  }

  if (action === 'archive') {
    if (!enterBusinessEntry()) return;
    client.sendMessage('COMMAND_RESULT', {
      command_id: cmdId,
      status: 'running',
      trace_id: traceId,
      result: {},
    });
    pendingSessionArchives.set(conversationId, {
      cmdId,
      traceId,
      client,
      cacheResult,
      lifecycle,
      timer: setTimeout(() => {
        settleSessionArchive(conversationId, false, 'session_archive_ack_timeout');
      }, SESSION_ARCHIVE_ACK_TIMEOUT_MS),
    });
    // Runtime-neutral gateway contract (bot_ws.py handles this message
    // for any bot): marks the gw_conversation_v2 row archived for this
    // device. Idempotent; records are kept for restore.
    client.sendMessage('SESSION.ARCHIVE', {
      conversation_id: conversationId,
      session_id: conversationId,
    });
    return;
  }

  // action === 'model_select'
  const model = normalizeStringValue(incoming?.model ?? payload?.model);
  if (!model) {
    rejectWith('model_required');
    return;
  }
  const known = lookupConversationBinding(conversationId);
  if (!known) {
    // No binding seen since process start: refuse instead of overriding
    // an arbitrary session. The next chat message re-registers it. Runtime
    // binding state loss → class=runtime (PLAN-0008 §4.5).
    rejectWith('session_binding_not_found');
    return;
  }
  if (!enterBusinessEntry()) return;
  setSessionModelOverride(known.sessionKey, model);
  log?.info?.(
    `[XiotBox] session.model.select cmd=${cmdId} conversation=${conversationId} model=${model}`,
  );
  const successPayload = {
    command_id: cmdId,
    status: 'success',
    trace_id: traceId,
    result: { model },
  };
  client.sendMessage('COMMAND_RESULT', successPayload);
  // Terminal ordering contract (XIOT-BUG-0050b R1): the terminal result is
  // cached first; only then is the execution ownership released, so a
  // duplicate arriving after release replays the cached result instead of
  // re-executing the action.
  cacheResult(cmdId, 'COMMAND_RESULT', successPayload);
  lifecycle.markTerminal(cmdId);
}

// ── Runtime visibility (XIOT-BUG-0007) ──
// The OpenClaw channel must present itself to the gateway as a first-class
// runtime, otherwise /v2/runtimes and orchestrator dispatch only ever see
// DSH. Payload contract matches gateway bot_ws._handle_runtimes_list;
// runtime_kind is declared explicitly because the gateway default is neutral
// by design (XIOT-BUG-0001 showed the cost of implicit runtime identity).
// workspaces stay empty until an OpenClaw workspace seam is specified; local
// paths never leave the bot.
//
// OPENCLAW_RUNTIME_KIND and the richer runtime profile now live in
// runtime-profile.ts (XIOT-BUG-0050a); re-export keeps the historical import
// surface intact for existing contract tests and callers.
export { OPENCLAW_RUNTIME_KIND } from './runtime-profile.js';

export function buildOpenclawRuntimeId(deviceId: string): string {
  const normalized = String(deviceId || '').trim();
  return normalized ? `openclaw-${normalized}` : '';
}

export function buildOpenclawRuntimeListPayload(deviceId: string, cfg?: any): {
  device_id: string;
  runtimes: Array<Record<string, unknown>>;
} {
  const normalized = String(deviceId || '').trim();
  const runtimeId = buildOpenclawRuntimeId(normalized);
  return {
    device_id: normalized,
    runtimes: runtimeId
      ? [
          {
            runtime_id: runtimeId,
            runtime_kind: OPENCLAW_RUNTIME_KIND,
            name: `OpenClaw (${normalized})`,
            status: 'online',
            // Resource facts only (XIOT-PLAN-0008 §3.2 rule 4): empty lists
            // mean "nothing published", never a capability tri-state.
            ...buildOpenclawResourceFacts(openclawWorkspaceAvailable(cfg)),
            // Explicit device capability declaration (XIOT-BUG-0050a),
            // published under the exact `capabilities` key the Gateway 0048a
            // contract reads (bot_ws._handle_runtimes_list →
            // runtime_profile.normalize_declaration). The declaration carries
            // command_ack=false, so the gateway derives contract_level=
            // "legacy" — 0050a never claims v1 (that is 0050b's ACK/DELIVERED
            // lifecycle).
            capabilities: buildOpenclawCapabilityDeclaration(),
          },
        ]
      : [],
  };
}

function resolveInboundContextEpoch(params: {
  incoming: any;
  deviceId: string;
  threadId: string;
  traceId?: string | null;
  messageId?: string | null;
  log?: any;
}): { epoch: number; source: 'explicit' | 'fallback' | 'default' } {
  const { incoming, deviceId, threadId, traceId, messageId, log } = params;
  const scopeKey = contextEpochScopeKey(deviceId, threadId);
  const explicitValue = incoming?.context_epoch ?? incoming?.contextEpoch;
  const hasExplicitContextEpoch = hasOwn(incoming, 'context_epoch') || hasOwn(incoming, 'contextEpoch');
  const now = Date.now();

  if (hasExplicitContextEpoch) {
    const epoch = normalizeContextEpoch(explicitValue);
    contextEpochCache.set(scopeKey, { epoch, updatedAt: now });
    pruneContextEpochCache();
    return { epoch, source: 'explicit' };
  }

  const cached = contextEpochCache.get(scopeKey);
  if (cached) {
    cached.updatedAt = now;
    contextEpochCache.set(scopeKey, cached);
    if (cached.epoch > 0) {
      log?.warn?.(JSON.stringify({
        event: 'context_epoch_missing_fallback',
        trace_id: traceId || '',
        message_id: messageId || '',
        device_id: deviceId,
        thread_id: normalizeThreadId(threadId),
        context_epoch: cached.epoch,
      }));
    }
    return { epoch: cached.epoch, source: 'fallback' };
  }

  return { epoch: 0, source: 'default' };
}

function resolveHomeDir(): string {
  const explicit = String(process.env.OPENCLAW_HOME || '').trim();
  const fallback = String(process.env.HOME || os.homedir() || process.cwd()).trim() || process.cwd();
  if (!explicit) return path.resolve(fallback);
  if (explicit === '~') return path.resolve(fallback);
  if (explicit.startsWith('~/') || explicit.startsWith('~\\')) {
    return path.resolve(path.join(fallback, explicit.slice(2)));
  }
  return path.resolve(explicit);
}

function expandUserPath(rawPath: string, homeDir: string): string {
  const normalized = String(rawPath || '').trim();
  if (!normalized) return normalized;
  if (normalized === '~') return homeDir;
  if (normalized.startsWith('~/') || normalized.startsWith('~\\')) {
    return path.join(homeDir, normalized.slice(2));
  }
  return normalized;
}

function resolveAgentIdFromSessionKey(sessionKey?: string | null): string {
  const raw = String(sessionKey || '').trim();
  const match = /^agent:([^:]+):/i.exec(raw);
  return match?.[1] ? normalizeAgentId(match[1]) : '';
}

function resolveSessionStorePath(cfg: any, sessionKey?: string | null): string {
  const homeDir = resolveHomeDir();
  const agentId = resolveAgentIdFromSessionKey(sessionKey) || resolveAgentId(cfg);
  const rawStore = String(cfg?.session?.store || '').trim();
  if (rawStore) {
    const withAgent = rawStore.includes('{agentId}')
      ? rawStore.split('{agentId}').join(agentId)
      : rawStore;
    return path.resolve(expandUserPath(withAgent, homeDir));
  }

  const stateOverride = String(
    process.env.OPENCLAW_STATE_DIR || process.env.CLAWDBOT_STATE_DIR || '',
  ).trim();
  const stateDir = stateOverride
    ? path.resolve(expandUserPath(stateOverride, homeDir))
    : path.resolve(path.join(homeDir, '.openclaw'));
  return path.resolve(stateDir, 'agents', agentId, 'sessions', 'sessions.json');
}

function loadSessionStore(storePath: string): Record<string, any> {
  try {
    const stat = fs.statSync(storePath);
    const mtimeMs = stat.mtimeMs || 0;
    const now = Date.now();
    if (
      sessionStoreCache &&
      sessionStoreCache.storePath === storePath &&
      sessionStoreCache.mtimeMs === mtimeMs &&
      now - sessionStoreCache.loadedAt < SESSION_STORE_CACHE_TTL_MS
    ) {
      return sessionStoreCache.store;
    }

    const raw = fs.readFileSync(storePath, 'utf-8');
    const parsed = raw ? JSON.parse(raw) : {};
    const store =
      parsed && typeof parsed === 'object' && !Array.isArray(parsed)
        ? (parsed as Record<string, any>)
        : {};
    sessionStoreCache = {
      storePath,
      mtimeMs,
      loadedAt: now,
      store,
    };
    return store;
  } catch {
    return {};
  }
}

function resolveSessionUsageSnapshot(cfg: any, sessionKey: string): SessionUsageSnapshot | null {
  const normalizedSessionKey = String(sessionKey || '').trim();
  if (!normalizedSessionKey) return null;
  const storePath = resolveSessionStorePath(cfg, sessionKey);
  const store = loadSessionStore(storePath);
  const entry =
    store[normalizedSessionKey] ||
    store[normalizedSessionKey.toLowerCase()] ||
    store[normalizedSessionKey.toUpperCase()] ||
    null;
  if (!entry || typeof entry !== 'object') return null;

  const inputTokens = normalizePositiveInt(entry.inputTokens);
  const outputTokens = normalizePositiveInt(entry.outputTokens);
  const explicitTotal = normalizePositiveInt(entry.totalTokens);
  const totalTokens =
    explicitTotal ?? ((inputTokens ?? 0) + (outputTokens ?? 0) > 0 ? (inputTokens ?? 0) + (outputTokens ?? 0) : undefined);
  if (totalTokens == null) return null;

  return {
    totalTokens,
    inputTokens,
    outputTokens,
    contextTokens: normalizePositiveInt(entry.contextTokens),
    totalTokensFresh: entry.totalTokensFresh === true,
    updatedAt: normalizePositiveInt(entry.updatedAt),
  };
}

async function waitForAbortSignal(abortSignal?: AbortSignal | null): Promise<void> {
  if (!abortSignal || abortSignal.aborted) {
    return;
  }
  await new Promise<void>((resolve) => {
    const onAbort = () => {
      abortSignal.removeEventListener('abort', onAbort);
      resolve();
    };
    abortSignal.addEventListener('abort', onAbort, { once: true });
  });
}

/**
 * Robust text extraction:
 * - supports common fields (markdown/text/body/output_text/etc.)
 * - supports arrays: parts/content/messages
 * - supports nested objects recursively (safe depth + cycle guard)
 * - supports streaming/delta-like fields
 */
function normalizeTextPayload(payload: any): string {
  if (typeof payload === 'string') return payload;
  if (!payload) return '';

  const acc: string[] = [];
  const visited = new WeakSet<object>();
  const MAX_DEPTH = 6;

  const pushText = (v: any) => {
    if (!v) return;
    if (typeof v === 'string') {
      const s = v.trimEnd();
      if (s) acc.push(s);
      return;
    }
    if (typeof v === 'number' || typeof v === 'boolean') {
      acc.push(String(v));
      return;
    }
    // objects handled by walk
  };

  const walk = (obj: any, depth: number) => {
    if (!obj || depth > MAX_DEPTH) return;
    if (typeof obj === 'string' || typeof obj === 'number' || typeof obj === 'boolean') {
      pushText(obj);
      return;
    }
    if (Array.isArray(obj)) {
      for (const it of obj) walk(it, depth + 1);
      return;
    }
    if (typeof obj !== 'object') return;

    if (visited.has(obj)) return;
    visited.add(obj);

    // 1) direct/common fields
    const directKeys = [
      'markdown',
      'text',
      'body',
      'content_text',
      'output_text',
      'outputText',
      'message',
      'message_text',
      'reply',
      'answer',
      'final',
      'final_text',
    ];
    for (const k of directKeys) {
      if (obj[k] !== undefined) {
        const v = obj[k];
        // sometimes message is nested object; allow recursion
        if (typeof v === 'object' && v) {
          walk(v, depth + 1);
        } else {
          pushText(v);
        }
      }
    }

    // 2) parts/content arrays
    if (Array.isArray(obj.parts)) walk(obj.parts, depth + 1);
    if (Array.isArray(obj.content)) walk(obj.content, depth + 1);

    // 3) common nested containers
    if (obj.content && typeof obj.content === 'object') walk(obj.content, depth + 1);
    if (obj.part && typeof obj.part === 'object') walk(obj.part, depth + 1);

    // 4) streaming/delta-ish
    // many providers use delta/content_delta/choices[].delta etc.
    if (obj.delta !== undefined) walk(obj.delta, depth + 1);
    if (obj.content_delta !== undefined) walk(obj.content_delta, depth + 1);
    if (Array.isArray(obj.choices)) walk(obj.choices, depth + 1);
    if (obj.choice && typeof obj.choice === 'object') walk(obj.choice, depth + 1);

    // 5) if this object looks like a "typed segment", try common patterns
    // e.g. {type:'text', text:'...'} or {type:'output_text', text:{value:'...'}}
    if (obj.type && (obj.text !== undefined || obj.value !== undefined || obj.content !== undefined)) {
      walk(obj.text, depth + 1);
      walk(obj.value, depth + 1);
      // obj.content already handled above
    }

    // 6) last resort: try a few known subkeys that often carry text
    const fallbackKeys = ['value', 'raw', 'display', 'caption', 'title'];
    for (const k of fallbackKeys) {
      if (obj[k] !== undefined) {
        const v = obj[k];
        if (typeof v === 'object' && v) walk(v, depth + 1);
        else pushText(v);
      }
    }
  };

  walk(payload, 0);

  // Join with newline to avoid "sticking" blocks together.
  return acc
    .map((s) => String(s))
    .filter((s) => s.trim().length > 0)
    .join('\n')
    .trim();
}

function normalizeReasoningPayload(payload: any): string {
  if (!payload || typeof payload !== 'object') return '';
  const reasoningKeys = [
    'reasoning',
    'thinking',
    'thought',
    'thoughts',
    'analysis',
    'rationale',
    'reasoning_text',
    'reasoningText',
    'thinking_text',
    'thinkingText',
  ];
  const parts: string[] = [];
  for (const key of reasoningKeys) {
    const value = (payload as any)?.[key];
    if (value == null) continue;
    const text = normalizeTextPayload(value);
    if (!text) continue;
    parts.push(text);
  }
  return parts.join('\n').trim();
}

function shouldSkipReply(text: string): boolean {
  const trimmed = (text || '').trim();
  if (!trimmed) return true;
  if (trimmed === 'NO_REPLY') return true;
  if (trimmed.endsWith('NO_REPLY')) return true;
  return false;
}

function readStringField(record: any, keys: string[]): string | undefined {
  if (!record || typeof record !== 'object') return undefined;
  for (const key of keys) {
    const value = normalizeStringValue(record?.[key]);
    if (value) return value;
  }
  return undefined;
}

function toUnknownArray(value: any): any[] {
  if (Array.isArray(value)) return value;
  if (value == null) return [];
  return [value];
}

function normalizeMediaEntry(entry: InboundMediaEntry | null | undefined): InboundMediaEntry | undefined {
  if (!entry) return undefined;
  const path = normalizeStringValue(entry.path);
  const url = normalizeStringValue(entry.url);
  const type = normalizeStringValue(entry.type);
  const normalizedPath = path || url;
  const normalizedUrl = url || path;
  if (!normalizedPath && !normalizedUrl) return undefined;
  return {
    path: normalizedPath,
    url: normalizedUrl,
    type,
  };
}

const MEDIA_PAYLOAD_KEYS = [
  'attachments',
  'files',
  'media',
  'media_items',
  'mediaItems',
  'attachment',
  'file',
  'image',
  'voice',
  'audio',
  'media_paths',
  'mediaPaths',
  'media_urls',
  'mediaUrls',
  'media_types',
  'mediaTypes',
  'media_path',
  'mediaPath',
  'media_url',
  'mediaUrl',
  'media_type',
  'mediaType',
];

function hasUsableMediaValue(value: any): boolean {
  if (value == null) return false;
  if (Array.isArray(value)) return value.length > 0;
  if (typeof value === 'string') return value.trim().length > 0;
  return true;
}

function hasMediaPayloadFields(container: any): boolean {
  if (!container || typeof container !== 'object' || Array.isArray(container)) return false;
  for (const key of MEDIA_PAYLOAD_KEYS) {
    if (!hasOwn(container, key)) continue;
    if (hasUsableMediaValue(container[key])) return true;
  }
  return false;
}

function resolveMediaCarrier(incoming: any): any {
  if (!incoming || typeof incoming !== 'object' || Array.isArray(incoming)) return incoming;
  if (hasMediaPayloadFields(incoming)) return incoming;
  const nested = incoming?.content;
  if (hasMediaPayloadFields(nested)) return nested;
  return incoming;
}

function hasInlineMediaMarker(item: any): boolean {
  return (
    hasOwn(item, 'file_name') ||
    hasOwn(item, 'fileName') ||
    hasOwn(item, 'name') ||
    hasOwn(item, 'mime_type') ||
    hasOwn(item, 'mimeType') ||
    hasOwn(item, 'content_type') ||
    hasOwn(item, 'contentType') ||
    hasOwn(item, 'media_type') ||
    hasOwn(item, 'mediaType') ||
    hasOwn(item, 'size_bytes') ||
    hasOwn(item, 'sizeBytes')
  );
}

function extensionFromMime(mimeType?: string): string {
  const mime = normalizeStringValue(mimeType)?.toLowerCase() || '';
  switch (mime) {
    case 'image/jpeg':
      return '.jpg';
    case 'image/png':
      return '.png';
    case 'image/gif':
      return '.gif';
    case 'image/webp':
      return '.webp';
    case 'image/heic':
      return '.heic';
    case 'application/pdf':
      return '.pdf';
    case 'text/plain':
      return '.txt';
    case 'text/markdown':
      return '.md';
    case 'text/x-python':
      return '.py';
    case 'application/json':
      return '.json';
    case 'audio/m4a':
      return '.m4a';
    case 'audio/wav':
      return '.wav';
    case 'audio/mpeg':
      return '.mp3';
    case 'audio/ogg':
      return '.ogg';
    default:
      return '';
  }
}

function readInlineMediaB64(item: any): string | undefined {
  const strict = readStringField(item, [
    'data_b64',
    'dataB64',
    'bytes_b64',
    'bytesB64',
    'file_b64',
    'fileB64',
  ]);
  const raw = strict || (() => {
    const generic = readStringField(item, ['base64', 'b64']);
    if (!generic) return undefined;
    return hasInlineMediaMarker(item) ? generic : undefined;
  })();
  if (!raw) return undefined;
  const dataUrlPrefix = /^data:[^;]+;base64,/i;
  if (dataUrlPrefix.test(raw)) {
    return raw.replace(dataUrlPrefix, '');
  }
  return raw;
}

function stageInlineMediaItem(item: any, params: { log?: any; traceId?: string | null; messageId?: string | null }): boolean {
  if (!item || typeof item !== 'object' || Array.isArray(item)) return false;
  const inlineB64 = readInlineMediaB64(item);
  if (!inlineB64) return false;
  try {
    const bytes = Buffer.from(inlineB64, 'base64');
    if (!bytes.length) return false;

    const fileName = readStringField(item, ['file_name', 'fileName', 'name']) || 'media.bin';
    const extFromName = path.extname(fileName);
    const mimeType = readStringField(item, ['mime_type', 'mimeType', 'content_type', 'contentType', 'media_type', 'mediaType']) || '';
    const ext = extFromName || extensionFromMime(mimeType) || '.bin';
    const stagedPath = path.join(
      os.tmpdir(),
      `xiotbox-inline-${Date.now()}-${Math.random().toString(16).slice(2)}${ext}`,
    );
    fs.writeFileSync(stagedPath, bytes);

    item.path = stagedPath;
    item.url = stagedPath;
    item.size_bytes = bytes.length;
    if (!item.mime_type && !item.mimeType && mimeType) {
      item.mime_type = mimeType;
    }
    return true;
  } catch (err: any) {
    params.log?.warn?.(JSON.stringify({
      event: 'inline_media_stage_failed',
      trace_id: params.traceId || '',
      message_id: params.messageId || '',
      error: err?.message || String(err),
    }));
    return false;
  }
}

export function stageInlineMediaPayload(incoming: any, params: { log?: any; traceId?: string | null; messageId?: string | null }): number {
  if (!incoming || typeof incoming !== 'object') return 0;
  const carrier = resolveMediaCarrier(incoming);
  if (!carrier || typeof carrier !== 'object') return 0;
  let stagedCount = 0;
  const collectionTargets = [
    carrier?.attachments,
    carrier?.files,
    carrier?.media,
    carrier?.media_items,
    carrier?.mediaItems,
  ];
  for (const target of collectionTargets) {
    for (const item of toUnknownArray(target)) {
      if (stageInlineMediaItem(item, params)) {
        stagedCount += 1;
      }
    }
  }

  const singularTargets = [
    carrier?.attachment,
    carrier?.file,
    carrier?.image,
    carrier?.voice,
    carrier?.audio,
  ];
  for (const target of singularTargets) {
    if (stageInlineMediaItem(target, params)) {
      stagedCount += 1;
    }
  }
  return stagedCount;
}

function parseMediaValue(item: any): InboundMediaEntry | undefined {
  if (item == null) return undefined;
  if (typeof item === 'string') {
    return normalizeMediaEntry({ path: item, url: item });
  }
  if (typeof item !== 'object' || Array.isArray(item)) return undefined;

  const path =
    readStringField(item, [
      'path',
      'local_path',
      'localPath',
      'file_path',
      'filePath',
      'media_path',
      'mediaPath',
      'absolute_path',
      'absolutePath',
      'staged_path',
      'stagedPath',
    ]) || readStringField(item, ['src', 'uri', 'href']);
  const url = readStringField(item, [
    'url',
    'media_url',
    'mediaUrl',
    'download_url',
    'downloadUrl',
    'file_url',
    'fileUrl',
    'remote_url',
    'remoteUrl',
  ]);
  const type = readStringField(item, [
    'mime_type',
    'mimeType',
    'content_type',
    'contentType',
    'media_type',
    'mediaType',
    'type',
  ]);

  return normalizeMediaEntry({ path, url, type });
}

function collectExplicitMediaEntries(incoming: any): InboundMediaEntry[] {
  const carrier = resolveMediaCarrier(incoming);
  const paths = toUnknownArray(carrier?.media_paths ?? carrier?.mediaPaths).map((value) =>
    normalizeStringValue(value),
  );
  const urls = toUnknownArray(carrier?.media_urls ?? carrier?.mediaUrls).map((value) =>
    normalizeStringValue(value),
  );
  const types = toUnknownArray(carrier?.media_types ?? carrier?.mediaTypes).map((value) =>
    normalizeStringValue(value),
  );

  const entries: InboundMediaEntry[] = [];
  const count = Math.max(paths.length, urls.length, types.length);
  for (let index = 0; index < count; index += 1) {
    const entry = normalizeMediaEntry({
      path: paths[index],
      url: urls[index],
      type: types[index],
    });
    if (entry) entries.push(entry);
  }

  const single = normalizeMediaEntry({
    path: readStringField(carrier, ['media_path', 'mediaPath']),
    url: readStringField(carrier, ['media_url', 'mediaUrl']),
    type: readStringField(carrier, ['media_type', 'mediaType']),
  });
  if (single) entries.push(single);

  return entries;
}

function collectStructuredMediaEntries(incoming: any): InboundMediaEntry[] {
  const carrier = resolveMediaCarrier(incoming);
  const collected: InboundMediaEntry[] = [];
  const fromLists = [
    carrier?.attachments,
    carrier?.files,
    carrier?.media,
    carrier?.media_items,
    carrier?.mediaItems,
  ];
  for (const list of fromLists) {
    for (const item of toUnknownArray(list)) {
      const entry = parseMediaValue(item);
      if (entry) collected.push(entry);
    }
  }

  const singular = [
    carrier?.attachment,
    carrier?.file,
    carrier?.image,
    carrier?.voice,
    carrier?.audio,
  ];
  for (const item of singular) {
    const entry = parseMediaValue(item);
    if (entry) collected.push(entry);
  }

  return collected;
}

function mergeMediaEntries(entries: InboundMediaEntry[]): InboundMediaEntry[] {
  const merged: InboundMediaEntry[] = [];
  const indexByKey = new Map<string, number>();

  for (const rawEntry of entries) {
    const entry = normalizeMediaEntry(rawEntry);
    if (!entry) continue;
    const key = `${entry.path || ''}|${entry.url || ''}`;
    const existingIndex = indexByKey.get(key);
    if (existingIndex == null) {
      indexByKey.set(key, merged.length);
      merged.push(entry);
      continue;
    }
    if (!merged[existingIndex]?.type && entry.type) {
      merged[existingIndex].type = entry.type;
    }
  }

  return merged;
}

export function buildInboundMediaContext(incoming: any): InboundMediaContextFields {
  const entries = mergeMediaEntries([
    ...collectExplicitMediaEntries(incoming),
    ...collectStructuredMediaEntries(incoming),
  ]);
  if (!entries.length) return {};

  const mediaPaths = entries.map((entry) => entry.path || '').filter(Boolean);
  if (!mediaPaths.length) return {};
  const mediaUrls = entries.map((entry) => entry.url || entry.path || '').filter(Boolean);
  const mediaTypes = entries.map((entry) => entry.type || '');

  const result: InboundMediaContextFields = {
    MediaPath: mediaPaths[0],
    MediaUrl: mediaUrls[0] || mediaPaths[0],
    MediaPaths: mediaPaths,
    MediaUrls: mediaUrls.length === mediaPaths.length ? mediaUrls : mediaPaths,
  };
  if (mediaTypes.some(Boolean)) {
    result.MediaTypes = mediaTypes;
    if (mediaTypes[0]) {
      result.MediaType = mediaTypes[0];
    }
  }
  return result;
}

function cloneConfig<T>(value: T): T {
  if (!value || typeof value !== 'object') return value;
  if (typeof (globalThis as any).structuredClone === 'function') {
    return (globalThis as any).structuredClone(value);
  }
  return JSON.parse(JSON.stringify(value)) as T;
}

function buildTextOnlyConfig(cfg: any): any {
  const cloned = cloneConfig(cfg);
  if (!cloned || typeof cloned !== 'object') return cfg;
  const tools = cloned.tools && typeof cloned.tools === 'object' ? { ...cloned.tools } : {};
  tools.allow = undefined;
  tools.alsoAllow = undefined;
  tools.deny = ['*'];
  cloned.tools = tools;
  return cloned;
}

// ── Hard-exit patterns: user explicitly wants to leave tool/control mode ──
const HARD_EXIT_PATTERNS = [
  /^\/stop\b/i,
  /^\/exit\b/i,
  /^\/quit\b/i,
  /^\/chat\b/i,
  /^\/text\b/i,
  /stop\s*control/i,
  /exit\s*control/i,
  /back\s*to\s*chat/i,
  /text\s*only/i,
  /text\s*mode/i,
];

const HARD_EXIT_COMMAND_ALIASES = [
  'exit control',
  'stop control',
  'quit control',
  'back to chat',
  'switch to chat',
  'resume chat',
  'chat only',
  'text only',
  'text mode',
  'leave control mode',
  '退出控制',
  '结束控制',
  '停止操控',
  '结束操控',
  '停止控制',
  '退出操控',
  '退出操作',
  '结束操作',
  '切回聊天',
  '恢复聊天',
  '只聊天',
  '仅聊天',
];

function normalizeAliasText(text: string): string {
  return String(text || '')
    .trim()
    .toLowerCase()
    .replace(/[。.!！?？,，;；:：()[\]{}"'“”‘’]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function isHardExitCommand(text: string): boolean {
  const trimmed = String(text || '').trim();
  if (!trimmed) return false;
  if (HARD_EXIT_PATTERNS.some((re) => re.test(trimmed))) return true;
  const normalized = normalizeAliasText(trimmed);
  return HARD_EXIT_COMMAND_ALIASES.some((alias) => normalized.includes(normalizeAliasText(alias)));
}

// ── Consecutive tool-only counter (keyed by thread+sender) ──
const MAX_CONSECUTIVE_TOOL_ONLY = 3;
const TOOL_ONLY_COUNTER_TTL_MS = 10 * 60 * 1000; // 10 min
const FORCE_EXIT_TTL_MS = 10 * 60 * 1000; // 10 min

interface ToolOnlyEntry {
  count: number;
  updatedAt: number;
  fingerprint: string;
}

const toolOnlyCounters = new Map<string, ToolOnlyEntry>();
const forceExitCounters = new Map<string, number>();

function toolOnlyCounterKey(
  deviceId: string,
  threadId: string,
  senderId: string,
): string {
  return `${deviceId}:${normalizeThreadId(threadId)}:${senderId}`;
}

function forceExitKey(deviceId: string, threadId: string): string {
  return `${deviceId}:${normalizeThreadId(threadId)}`;
}

function isLikelyNonSubstantiveAck(text: string): boolean {
  const normalized = (text || '').trim();
  if (!normalized) return true;
  const compact = normalizeAliasText(normalized).replace(/\s+/g, '');
  const exactAcks = new Set([
    'operationcompleted',
    'operationcomplete',
    'completed',
    'complete',
    '操作已完成',
    '操作完成',
    '已完成',
    '完成',
    'done',
    'ok',
    'okay',
    'success',
    'successful',
    'completed',
    'taskcompleted',
    'processingcompleted',
    '任务已完成',
    '处理完成',
  ]);
  if (exactAcks.has(compact)) return true;
  if (
    compact.length <= 20 &&
    (
      compact.includes('operationcompleted') ||
      compact.includes('taskcompleted') ||
      compact.includes('操作已完成') ||
      compact.includes('任务已完成')
    )
  ) {
    return true;
  }
  return false;
}

function buildToolOnlyFingerprint(params: {
  branch: 'tool_only' | 'no_reply' | 'ack_only' | 'empty';
  text: string;
  toolNames: string[];
  sawControlToolSignal: boolean;
  sawInProgressSignal: boolean;
}): string {
  const compactText = (params.text || '')
    .trim()
    .toLowerCase()
    .replace(/\s+/g, '')
    .replace(/[。.!！?？,，;；:]/g, '')
    .slice(0, 64);
  const uniqTools = Array.from(
    new Set(
      params.toolNames
        .map((name) => String(name || '').trim().toLowerCase())
        .filter(Boolean),
    ),
  ).sort();
  return [
    `b=${params.branch}`,
    `t=${compactText || '-'}`,
    `tools=${uniqTools.join(',') || '-'}`,
    `ctrl=${params.sawControlToolSignal ? '1' : '0'}`,
    `prog=${params.sawInProgressSignal ? '1' : '0'}`,
  ].join('|');
}

function incrementToolOnlyCounter(key: string, fingerprint: string): number {
  const now = Date.now();
  const existing = toolOnlyCounters.get(key);
  if (existing && now - existing.updatedAt < TOOL_ONLY_COUNTER_TTL_MS) {
    if (existing.fingerprint === fingerprint) {
      existing.count += 1;
    } else {
      existing.count = 1;
      existing.fingerprint = fingerprint;
    }
    existing.updatedAt = now;
    return existing.count;
  }
  toolOnlyCounters.set(key, { count: 1, updatedAt: now, fingerprint });
  return 1;
}

function resetToolOnlyCounter(key: string): void {
  toolOnlyCounters.delete(key);
}

function pruneToolOnlyCounters(): void {
  const now = Date.now();
  for (const [k, v] of toolOnlyCounters.entries()) {
    if (now - v.updatedAt > TOOL_ONLY_COUNTER_TTL_MS) {
      toolOnlyCounters.delete(k);
    }
  }
}

function scheduleForceExit(key: string): void {
  forceExitCounters.set(key, Date.now() + FORCE_EXIT_TTL_MS);
}

function consumeForceExit(key: string): boolean {
  const until = forceExitCounters.get(key);
  if (!until) return false;
  if (Date.now() > until) {
    forceExitCounters.delete(key);
    return false;
  }
  forceExitCounters.delete(key);
  return true;
}

function pruneForceExitCounters(): void {
  const now = Date.now();
  for (const [k, until] of forceExitCounters.entries()) {
    if (now > until) {
      forceExitCounters.delete(k);
    }
  }
}

function isConfiguredCfg(cfg: any): boolean {
  return listAccountIds(cfg).length > 0;
}

function detectToolSignals(outPayload: any): boolean {
  if (!outPayload || typeof outPayload !== 'object') return false;
  return Boolean(
    outPayload.tool_calls ||
    outPayload.toolCalls ||
    outPayload.tool_call ||
    outPayload.function_call ||
    outPayload.functionCall ||
    outPayload.action ||
    outPayload.actions ||
    outPayload.observation ||
    outPayload.observations ||
    outPayload.tool_result ||
    outPayload.toolResult,
  );
}

function extractToolSignalNames(outPayload: any): string[] {
  if (!outPayload || typeof outPayload !== 'object') return [];
  const names: string[] = [];
  const tc = outPayload.tool_calls || outPayload.toolCalls;
  if (Array.isArray(tc)) {
    for (const t of tc) {
      const name = t?.name || t?.tool || t?.tool_name || t?.function?.name;
      if (name) names.push(String(name));
    }
  }
  const fc = outPayload.function_call || outPayload.functionCall;
  if (fc?.name) names.push(String(fc.name));
  const act = outPayload.action;
  if (typeof act === 'string') names.push(act);
  return Array.from(new Set(names.map((s) => String(s || '').trim()).filter(Boolean)));
}

function isLikelyControlToolName(name: string): boolean {
  const normalized = String(name || '').trim().toLowerCase();
  if (!normalized) return false;
  return (
    normalized.includes('xiotbox_control') ||
    normalized === 'control' ||
    normalized.endsWith('_control') ||
    normalized.includes('device_control') ||
    normalized.includes('android_control') ||
    normalized.includes('ios_control') ||
    normalized.includes('adb_control')
  );
}

const IN_PROGRESS_HINTS = [
  'running',
  'in_progress',
  'inprogress',
  'in progress',
  'pending',
  'processing',
  'working',
  'executing',
  'queued',
  'please wait',
  '进行中',
  '处理中',
  '执行中',
  '等待中',
];

function isLikelyInProgressText(text: string): boolean {
  const normalized = normalizeAliasText(text);
  if (!normalized) return false;
  return IN_PROGRESS_HINTS.some((hint) => normalized.includes(normalizeAliasText(hint)));
}

function hasInProgressSignal(outPayload: any): boolean {
  if (!outPayload || typeof outPayload !== 'object') return false;
  const visited = new Set<any>();
  const stack: any[] = [outPayload];
  let depth = 0;
  while (stack.length && depth < 200) {
    depth += 1;
    const current = stack.pop();
    if (!current || typeof current !== 'object') continue;
    if (visited.has(current)) continue;
    visited.add(current);
    for (const [rawKey, value] of Object.entries(current)) {
      const key = String(rawKey || '').toLowerCase();
      if (typeof value === 'string') {
        const checkable =
          key === 'status' ||
          key === 'state' ||
          key === 'phase' ||
          key === 'stage' ||
          key.endsWith('_status') ||
          key.endsWith('_state') ||
          key.includes('progress');
        if (checkable && isLikelyInProgressText(value)) {
          return true;
        }
      } else if (typeof value === 'number') {
        if (key.includes('progress') && value >= 0 && value < 100) {
          return true;
        }
      } else if (Array.isArray(value)) {
        for (const item of value) stack.push(item);
      } else if (value && typeof value === 'object') {
        stack.push(value);
      }
    }
  }
  return false;
}

function compactProgressText(value: any, maxLen: number = 80): string {
  const text = String(value || '').replace(/\s+/g, ' ').trim();
  if (!text) return '';
  return text.length > maxLen ? `${text.slice(0, Math.max(0, maxLen - 1))}…` : text;
}

function normalizeProgressPercent(value: any): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) {
    if (value >= 0 && value <= 1) return Math.round(value * 100);
    if (value >= 0 && value <= 100) return Math.round(value);
    return undefined;
  }

  if (typeof value === 'string') {
    const compact = value.trim();
    if (!compact) return undefined;
    const percentMatch = compact.match(/(-?\d+(?:\.\d+)?)\s*%/);
    if (percentMatch) {
      const parsed = Number(percentMatch[1]);
      if (Number.isFinite(parsed) && parsed >= 0 && parsed <= 100) {
        return Math.round(parsed);
      }
      return undefined;
    }
    const parsed = Number(compact);
    if (Number.isFinite(parsed)) {
      if (parsed >= 0 && parsed <= 1 && compact.includes('.')) {
        return Math.round(parsed * 100);
      }
      if (parsed >= 0 && parsed <= 100) {
        return Math.round(parsed);
      }
    }
    return undefined;
  }

  if (value && typeof value === 'object') {
    const current = normalizePositiveInt(
      (value as any).current ??
      (value as any).done ??
      (value as any).completed ??
      (value as any).step ??
      (value as any).processed,
    );
    const total = normalizePositiveInt(
      (value as any).total ??
      (value as any).max ??
      (value as any).steps ??
      (value as any).count,
    );
    if (current != null && total != null && total > 0) {
      const ratio = (current / total) * 100;
      const bounded = Math.max(0, Math.min(100, Math.round(ratio)));
      return bounded;
    }
  }
  return undefined;
}

function extractProgressSnapshot(outPayload: any): ProgressSnapshot | null {
  if (!outPayload || typeof outPayload !== 'object') return null;

  const snapshot: ProgressSnapshot = {};
  const visited = new Set<any>();
  const stack: any[] = [outPayload];
  let depth = 0;

  while (stack.length && depth < 250) {
    depth += 1;
    const current = stack.pop();
    if (!current || typeof current !== 'object') continue;
    if (visited.has(current)) continue;
    visited.add(current);

    for (const [rawKey, value] of Object.entries(current)) {
      const key = String(rawKey || '').toLowerCase();
      const keyHasProgressHint =
        key.includes('progress') || key.includes('percent') || key.includes('pct');
      const keyIsStatus =
        key === 'status' ||
        key === 'state' ||
        key === 'phase' ||
        key.endsWith('_status') ||
        key.endsWith('_state');
      const keyIsStage =
        key === 'stage' ||
        key === 'step' ||
        key === 'task' ||
        key.endsWith('_stage') ||
        key.endsWith('_step');
      const keyIsDetail =
        key === 'detail' ||
        key === 'message' ||
        key === 'summary' ||
        key === 'title' ||
        key === 'reason' ||
        key.endsWith('_detail');

      if (snapshot.progressPercent == null && (keyHasProgressHint || key === 'current' || key === 'total')) {
        const percent = normalizeProgressPercent(value);
        if (percent != null) {
          snapshot.progressPercent = percent;
        }
      }

      if (typeof value === 'string') {
        const compact = compactProgressText(value);
        if (!compact) continue;

        if (!snapshot.status && (keyIsStatus || (keyHasProgressHint && isLikelyInProgressText(compact)))) {
          snapshot.status = compact;
          continue;
        }

        if (!snapshot.stage && keyIsStage) {
          snapshot.stage = compact;
          continue;
        }

        if (!snapshot.detail && keyIsDetail && compact.length <= 80) {
          snapshot.detail = compact;
          continue;
        }

        if (!snapshot.status && isLikelyInProgressText(compact) && compact.length <= 80) {
          snapshot.status = compact;
        }
      } else if (Array.isArray(value)) {
        for (const item of value) stack.push(item);
      } else if (value && typeof value === 'object') {
        if (snapshot.progressPercent == null && (key === 'progress' || keyHasProgressHint)) {
          const percent = normalizeProgressPercent(value);
          if (percent != null) {
            snapshot.progressPercent = percent;
          }
        }
        stack.push(value);
      }
    }
  }

  if (
    snapshot.status == null &&
    snapshot.stage == null &&
    snapshot.detail == null &&
    snapshot.progressPercent == null
  ) {
    return null;
  }

  return snapshot;
}

function buildProgressRunningText(params: {
  toolNames: string[];
  snapshot: ProgressSnapshot | null;
  fallbackText?: string;
}): string {
  const uniqTools = Array.from(
    new Set(
      (params.toolNames || [])
        .map((name) => compactProgressText(name, 48))
        .filter(Boolean),
    ),
  );
  const snapshot = params.snapshot;
  const segments: string[] = [];

  if (snapshot?.stage) segments.push(snapshot.stage);
  if (snapshot?.status) segments.push(snapshot.status);
  if (snapshot?.progressPercent != null) segments.push(`${snapshot.progressPercent}%`);
  if (!segments.length && snapshot?.detail) segments.push(snapshot.detail);
  if (!segments.length && uniqTools.length) segments.push(uniqTools.join(', '));

  const fallbackText = compactProgressText(params.fallbackText, 80);
  if (!segments.length && fallbackText && isLikelyInProgressText(fallbackText)) {
    segments.push(fallbackText);
  }

  if (!segments.length) return 'Running, please wait…';
  return `Running: ${segments.join(' · ')}`;
}

function buildProgressFingerprint(params: {
  kind: string;
  toolNames: string[];
  snapshot: ProgressSnapshot | null;
  fallbackText?: string;
}): string {
  const uniqTools = Array.from(
    new Set(
      (params.toolNames || [])
        .map((name) => String(name || '').trim().toLowerCase())
        .filter(Boolean),
    ),
  ).sort();
  const snapshot = params.snapshot;
  return [
    `k=${String(params.kind || '').trim() || '-'}`,
    `tools=${uniqTools.join(',') || '-'}`,
    `status=${(snapshot?.status || '').toLowerCase().trim() || '-'}`,
    `stage=${(snapshot?.stage || '').toLowerCase().trim() || '-'}`,
    `detail=${(snapshot?.detail || '').toLowerCase().trim() || '-'}`,
    `progress=${snapshot?.progressPercent ?? '-'}`,
    `text=${compactProgressText(params.fallbackText, 48).toLowerCase() || '-'}`,
  ].join('|');
}

function buildRunningStreamEvents(params: {
  toolNames: string[];
  snapshot: ProgressSnapshot | null;
  fallbackText?: string;
  thinkingText?: string;
}): StreamEvent[] {
  const events: StreamEvent[] = [];
  const toolNames = Array.from(
    new Set(
      (params.toolNames || [])
        .map((name) => compactProgressText(name, 48))
        .filter(Boolean),
    ),
  );
  const latestTool = toolNames.length ? toolNames[toolNames.length - 1] : '';
  const snapshot = params.snapshot;
  const progressText = buildProgressRunningText({
    toolNames,
    snapshot,
    fallbackText: params.fallbackText,
  });
  const toolSummarySource =
    snapshot?.stage ||
    snapshot?.status ||
    snapshot?.detail ||
    compactProgressText(params.fallbackText, 64);
  const toolSummary = compactProgressText(toolSummarySource, 48);
  const thinkingText = String(params.thinkingText || '').trim();

  events.push({
    type: 'tool_call',
    id: 'tool_running_primary',
    status: 'running',
    tool_name: latestTool || 'exec',
    tool_label: latestTool || 'running',
    tool_icon: 'terminal',
    params_summary: toolSummary || compactProgressText(progressText, 48),
    detail: progressText,
    collapsible: false,
  });

  if (snapshot?.progressPercent != null) {
    events.push({
      type: 'progress',
      id: 'progress_running_primary',
      status: 'running',
      message: progressText,
      percent: snapshot.progressPercent,
    });
  }

  if (thinkingText) {
    events.push({
      type: 'thinking',
      id: 'thinking_running_primary',
      status: 'streaming',
      content: thinkingText,
    });
  }

  return events;
}

function summarizeToolSignals(outPayload: any): string {
  const uniq = extractToolSignalNames(outPayload);
  if (!uniq.length) return '';
  return `tool=${uniq.join(',')}`;
}

export const xiotboxPlugin = {
  id: CHANNEL_ID,
  meta: {
    id: CHANNEL_ID,
    label: 'XiotBox',
    selectionLabel: 'XiotBox Gateway',
    blurb: 'Connects XiotBox devices and dispatches messages to OpenClaw runtime.',
    docsPath: 'README.md',
    order: 100,
  },
  capabilities: {
    chatTypes: ['direct'],
    reactions: false,
    threads: true,
    media: true,
    nativeCommands: false,
    blockStreaming: true,
    outbound: true,
  },
  reload: { configPrefixes: ['channels.xiotbox'] },
  approvalCapability: xiotboxApprovalCapability,
  messaging: {
    targetResolver: {
      looksLikeId: (raw: string) => Boolean(raw && raw.trim()),
      resolveTarget: async (params: { normalized: string }) => {
        const to = String(params?.normalized ?? '').trim();
        if (!to) return null;
        // XiotBox is a single-device direct channel: any conversation/thread id
        // resolves to a direct "user" target for that conversation. The actual
        // wire routing uses threadId via the direct-send path.
        return { to, kind: 'user', source: 'normalized' };
      },
    },
  },
  outbound: {
    deliveryMode: 'direct',
    sendText: async (ctx: any) => {
      try {
        console.error(
          `[xiotbox-send] sendText called to=${ctx?.to} threadId=${ctx?.threadId} accountId=${ctx?.accountId}`,
        );
      } catch {}
      const sender = getDirectSender(ctx?.accountId || 'default');
      if (!sender) {
        console.error('[xiotbox-send] NO DIRECT SENDER');
        throw new Error('xiotbox outbound sender unavailable');
      }
      // When the core delivers a subagent-settle summary through the outbound
      // adapter, ctx.threadId is often missing and ctx.to carries the
      // conversation id. Resolve the original parent command/thread so the
      // Gateway updates the SAME gw_message row instead of creating a new
      // direct_* id that never persists.
      const deliveryContext = resolvePendingSubagentDeliveryByConversation(ctx?.to);
      const resolvedCommandId =
        (deliveryContext?.commandId || '').trim() ||
        (ctx?.commandId ? String(ctx.commandId) : '') ||
        undefined;
      const resolvedThreadId =
        (deliveryContext?.threadId || '').trim() ||
        (ctx?.threadId ? String(ctx.threadId) : undefined);
      const result = sender({
        text: ctx?.text || '',
        commandId: resolvedCommandId,
        threadId: resolvedThreadId,
        traceId: deliveryContext?.traceId || ctx?.identity?.id || null,
      });
      try {
        console.error(
          `[xiotbox-send] result delivered=${result.delivered} error=${result.error || ''}`,
        );
      } catch {}
      if (!result.delivered) {
        throw new Error(result.error || 'xiotbox outbound delivery failed');
      }
      return {
        channel: CHANNEL_ID,
        messageId: result.commandId || '',
        conversationId: ctx?.to || undefined,
        timestamp: Date.now(),
      };
    },
    // Fallback for core-initiated or delayed approval deliveries. Replies from
    // XiotBox inbound dispatch are observed in deliver() above because that
    // direct COMMAND_RESULT path bypasses the standard outbound adapter.
    afterDeliverPayload: async (params: any) => {
      handleOutboundApprovalPayload({
        accountId: params?.target?.accountId || 'default',
        payload: params?.payload,
        conversationId: params?.target?.threadId,
      });
      handleOutboundAskUserPayload({
        accountId: params?.target?.accountId || 'default',
        payload: params?.payload,
        conversationId: params?.target?.threadId,
      });
    },
  },
  config: {
    listAccountIds: (cfg: any): string[] => listAccountIds(cfg),
    resolveAccount: (cfg: any, accountId?: string) => resolveAccount(cfg, accountId),
    defaultAccountId: (cfg: any) => resolveDefaultAccountId(cfg),
    isConfigured: (account: any) =>
      Boolean(account?.config?.DEVICE_ID && account?.config?.DEVICE_TOKEN),
    describeAccount: (account: any) => {
      const accountId = normalizeAccountId(account?.accountId);
      const active = describeGatewayAccountState(accountId);
      return {
        accountId,
        name: account.config?.name || 'XiotBox',
        enabled: account.enabled,
        configured: Boolean(account.config?.DEVICE_ID && account.config?.DEVICE_TOKEN),
        connected: active.connected,
        startedAt: active.startedAt,
        lastConnectedAt: active.lastConnectedAt,
      };
    },
  },
  gateway: {
    startAccount: async (ctx: GatewayStartContextLike) => {
      const { cfg, log, abortSignal } = ctx;
      const accountId = normalizeAccountId(ctx?.accountId);
      const instanceId = nextGatewayInstanceId();
      const finalCfg = buildConfig(getChannelConfig(cfg));
      const openclawRuntimeId = buildOpenclawRuntimeId(finalCfg.DEVICE_ID);
      const workspaceRegistry = buildOpenclawWorkspaceRegistry(openclawRuntimeId, cfg);
      updateGatewayStatus(ctx, accountId, {
        running: true,
        connected: false,
        lastStatusAt: Date.now(),
        detail: 'starting',
      }, log);
      log?.info?.(
        `[XiotBox][${accountId}] remote streaming config ` +
          `(STREAMING=${finalCfg.STREAMING}, ` +
          `BLOCK_STREAMING=${finalCfg.BLOCK_STREAMING}, ` +
          `PROGRESS_UPDATES=${finalCfg.PROGRESS_UPDATES})`,
      );

      if (!finalCfg.DEVICE_ID || !finalCfg.DEVICE_TOKEN) {
        const err = `Missing XiotBox configuration (DEVICE_ID or DEVICE_TOKEN) for account "${accountId}".`;
        log?.error?.(`[XiotBox][${accountId}] ${err}`);
        throw new Error(err);
      }

      const existing = getGatewayAccount(accountId);
      if (existing) {
        log?.warn?.(
          `[XiotBox][${accountId}] startAccount called while an instance is already active ` +
            `(old_instance=${existing.instanceId}, new_instance=${instanceId})`,
        );
        if (existing.stop) {
          try {
            await existing.stop('replaced_by_new_start');
          } catch (err: any) {
            log?.warn?.(
              `[XiotBox][${accountId}] failed to stop previous gateway instance: ${err?.message || err}`,
            );
          }
        }
      }

      registerGatewayAccount(accountId, {
        instanceId,
        startedAt: Date.now(),
        stop: null,
      });
      const isCurrentInstance = () => getGatewayAccount(accountId)?.instanceId === instanceId;

      const client = new WSSClient(finalCfg);
      const eventOutbox = new DurableEventOutbox({
        filePath: resolveEventOutboxPath(finalCfg.DEVICE_ID),
        send: (eventPayload) => client.sendMessage('V2.EVENT', eventPayload),
        logger: log,
      });
      const unregisterApprovalAccount = registerApprovalLifecycleAccount({
        accountId,
        deviceId: finalCfg.DEVICE_ID,
        emit: (eventPayload) => eventOutbox.enqueue(eventPayload),
      });
      const unregisterAskUserAccount = registerAskUserLifecycleAccount({
        accountId,
        deviceId: finalCfg.DEVICE_ID,
        emit: (eventPayload) => eventOutbox.enqueue(eventPayload),
      });
      const unregisterMemoryAccount = registerMemoryLifecycleAccount({
        accountId,
        deviceId: finalCfg.DEVICE_ID,
        emit: (eventPayload) => eventOutbox.enqueue(eventPayload),
      });
      const unregisterSubagentAccount = registerSubagentLifecycleAccount({
        accountId,
        deviceId: finalCfg.DEVICE_ID,
        emit: (eventPayload) => eventOutbox.enqueue(eventPayload),
        logger: log,
      });
      let stopPromise: Promise<void> | null = null;
      let unregisterDirectSender: () => void = () => {};
      const stopCurrent = async (reason = 'stop') => {
        if (stopPromise) {
          return stopPromise;
        }
        stopPromise = (async () => {
          removeGatewayAccount(accountId, instanceId);
          updateGatewayStatus(ctx, accountId, {
            running: false,
            connected: false,
            lastDisconnectedAt: Date.now(),
            lastStatusAt: Date.now(),
            detail: reason,
          }, log);
          log?.info?.(`[XiotBox][${accountId}] Stopping channel instance=${instanceId} reason=${reason}`);
          unregisterApprovalAccount();
          unregisterAskUserAccount();
          unregisterMemoryAccount();
          unregisterSubagentAccount();
          unregisterDirectSender();
          eventOutbox.stop();
          await client.disconnect();
        })();
        return stopPromise;
      };
      registerGatewayAccount(accountId, {
        instanceId,
        startedAt: Date.now(),
        stop: stopCurrent,
      });
      const replyApi = getReplyApi(ctx);
      const dispatchReply = replyApi?.dispatchReplyWithBufferedBlockDispatcher;

      if (!dispatchReply) {
        const err = 'dispatchReplyWithBufferedBlockDispatcher not available in channel runtime.';
        log?.error?.(`[XiotBox] ${err}`);
        updateGatewayStatus(ctx, accountId, {
          running: false,
          connected: false,
          lastStatusAt: Date.now(),
          detail: 'runtime_unavailable',
          error: err,
        }, log);
        throw new Error(err);
      }

      const commandCache = new Map<string, any>();
      // Canonical v1 command lifecycle evidence (XIOT-BUG-0050b): COMMAND_ACK
      // / COMMAND_DELIVERED emission with per-command idempotency.
      const commandLifecycle = new CommandLifecycleEmitter(
        (type: string, payload: any) => client.sendMessage(type, payload),
        { ttlMs: Number(finalCfg.COMMAND_CACHE_TTL_MS) || undefined },
      );
      const e2e = new OpenClawE2E(finalCfg, log);
      e2e.init();
      try {
        await e2e.refreshPeerKey();
      } catch (err: any) {
        log?.warn?.(`[XiotBox] E2E peer key not ready: ${err?.message || err}`);
      }

      finalCfg.HELLO_EXTRA = {
        e2e: e2e.helloPayload(),
        thread_id: normalizeThreadId(e2e.threadId),
      };
      // Ensure the very first HELLO after connect carries E2E identity claim.
      // WSSClient captures HELLO_EXTRA during construction; update it explicitly.
      client.setHelloExtra(finalCfg.HELLO_EXTRA);

      // Register a direct (channel-originated) send path used by the outbound
      // adapter for subagent-completion announce and exec-approval followups.
      // It mirrors buildEncryptedResult but targets the peer directory instead
      // of a single inbound command envelope.
      unregisterDirectSender = registerDirectSender(accountId, ({ text, commandId, threadId, traceId }) => {
        const peers = e2e.directReplyPeers();
        if (!peers.length) {
          return { delivered: false, error: 'no_e2e_peers' };
        }
        const resolvedCommandId =
          String(commandId || '').trim() ||
          `direct_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`;
        const resolvedThreadId = normalizeThreadId(threadId || e2e.threadId);
        const e2eMulti: Record<string, any> = {};
        let primaryEnv: any = null;
        let primaryKeyId = '';
        for (const peer of peers) {
          const envOut = e2e.encryptText(
            text,
            {
              direction: 'p2c',
              device_id: finalCfg.DEVICE_ID,
              thread_id: resolvedThreadId,
              command_id: resolvedCommandId,
              content_type: 'text/markdown',
              chunk_seq: 0,
              enc_v: e2e.encV,
            },
            { publicKey: peer.publicKey, keyId: peer.keyId },
          );
          const envKeyId = peer.keyId || envOut?.key_id || '';
          if (!primaryEnv) {
            primaryEnv = envOut;
            primaryKeyId = envKeyId;
          }
          e2eMulti[envKeyId || `peer_${Object.keys(e2eMulti).length}`] = envOut;
        }
        client.sendMessage('COMMAND_RESULT', {
          command_id: resolvedCommandId,
          thread_id: resolvedThreadId,
          status: 'success',
          trace_id: traceId || null,
          result: {
            e2e: primaryEnv,
            e2e_multi: e2eMulti,
            result_key_id: primaryKeyId,
            enc_v: e2e.encV,
            content_type: 'text/markdown',
            chunk_seq: 0,
            thread_id: resolvedThreadId,
          },
        });
        return { delivered: true, commandId: resolvedCommandId };
      });

      const pruneCache = () => {
        const now = Date.now();
        for (const [id, entry] of commandCache.entries()) {
          if (now - entry.ts > finalCfg.COMMAND_CACHE_TTL_MS) {
            commandCache.delete(id);
          }
        }
        while (commandCache.size > finalCfg.COMMAND_CACHE_MAX) {
          const firstKey = commandCache.keys().next().value;
          commandCache.delete(firstKey);
        }
      };

      const getCached = (cmdId: string) => {
        pruneCache();
        const entry = commandCache.get(cmdId);
        return entry ? { type: entry.type || 'COMMAND_RESULT', payload: entry.payload } : null;
      };

      // COMMAND_RESULT terminal results. Every call site is post-claim: the
      // terminal payload is cached BEFORE the execution ownership is released
      // (XIOT-BUG-0050b R1) so a duplicate arriving after release replays the
      // cached terminal — there is no re-execution window.
      const setCached = (cmdId: string, payload: any) => {
        pruneCache();
        commandCache.set(cmdId, { ts: Date.now(), type: 'COMMAND_RESULT', payload });
        commandLifecycle.markTerminal(cmdId);
      };

      // Non-COMMAND_RESULT terminal frames (canonical ACK rejections,
      // XIOT-BUG-0050b) replay with their own frame type on redelivery.
      // Rejections never held execution ownership, so no release here.
      const setCachedFrame = (cmdId: string, type: string, payload: any) => {
        pruneCache();
        commandCache.set(cmdId, { ts: Date.now(), type, payload });
      };

      // Session command handler (XIOT-BUG-0006). Runs before the chat/E2E
      // path: session.* commands carry plain JSON without an OGE2E1 envelope.
      // Canonical ACK/DELIVERED lifecycle emission lives in
      // dispatchSessionCommand (XIOT-BUG-0050b).
      const handleSessionCommand = (args: {
        action: 'model_select' | 'archive' | 'interrupt' | 'unsupported';
        payload: any;
        incoming: any;
        cmdId: string;
        traceId: string | null;
      }): void => {
        dispatchSessionCommand(
          {
            client,
            lifecycle: commandLifecycle,
            // Session-command cacheResult doubles as the terminal cache+release
            // path: rejections never held ownership (markTerminal is a no-op
            // for them), while model.select success / archive settle write the
            // terminal and then release ownership — in that order.
            cacheResult: (cmdId: string, type: string, payload: any) => {
              setCachedFrame(cmdId, type, payload);
              commandLifecycle.markTerminal(cmdId);
            },
            cachedResult: getCached,
            log,
            deviceId: finalCfg.DEVICE_ID,
          },
          args,
        );
      };

      const handleWorkspaceCommand = async (args: {
        commandType: string;
        incoming: Record<string, unknown>;
        cmdId: string;
        traceId: string | null;
      }): Promise<void> => {
        const cached = getCached(args.cmdId);
        if (cached) {
          client.sendMessage(cached.type, cached.payload);
          return;
        }
        if (!commandLifecycle.ackAccepted(args.cmdId, args.traceId)) {
          commandLifecycle.replayLifecycleEvidence(args.cmdId);
          return;
        }
        commandLifecycle.markDelivered(args.cmdId);
        try {
          const result = await executeWorkspaceControl(
            workspaceRegistry,
            args.commandType,
            args.incoming,
          );
          const terminalPayload = {
            command_id: args.cmdId,
            status: 'success',
            trace_id: args.traceId,
            result,
          };
          client.sendMessage('COMMAND_RESULT', terminalPayload);
          setCached(args.cmdId, terminalPayload);
        } catch (err: any) {
          const terminalPayload = {
            command_id: args.cmdId,
            status: 'failed',
            trace_id: args.traceId,
            error: err instanceof Error ? err.message : String(err),
            result: err?.details && typeof err.details === 'object' ? { details: err.details } : {},
          };
          client.sendMessage('COMMAND_RESULT', terminalPayload);
          setCached(args.cmdId, terminalPayload);
        }
      };

      client.on('SESSION.ARCHIVE_ACK', (ackPayload: any) => {
        settleSessionArchiveAck(ackPayload);
      });

      // ── SESSION.REGISTER (XIOT-BUG-0007) ──
      // Registers each bound conversation with the gateway so bot-side
      // OpenClaw sessions appear in the conversation list. The gateway
      // derives the same session_key shape as the client binding path and
      // never clobbers an existing client binding (conversation_id UNIQUE).
      const sessionRegisterSent = new Set<string>();
      const sendSessionRegister = (entry: {
        conversationId: string;
        agentId: string;
        contextEpoch: number;
      }) => {
        const conversationId = String(entry.conversationId || '').trim();
        if (!conversationId || sessionRegisterSent.has(conversationId)) return;
        sessionRegisterSent.add(conversationId);
        client.sendMessage('SESSION.REGISTER', {
          runtime_kind: OPENCLAW_RUNTIME_KIND,
          session_id: conversationId,
          conversation_id: conversationId,
          agent_id: entry.agentId,
          context_epoch: entry.contextEpoch,
          projection_version: 1,
          // Same device capability declaration as RUNTIMES.LIST (XIOT-BUG-
          // 0050a): Gateway 0048a register_bot_session reads `capabilities`
          // here too, so both declaration surfaces (the runtimes registry and
          // conversation registration) carry one identical object and cannot
          // drift apart.
          capabilities: buildOpenclawCapabilityDeclaration(),
        });
      };

      client.on('SESSION.REGISTER_ACK', (ackPayload: any) => {
        const data = ackPayload?.payload || ackPayload || {};
        if (data.ok === false) {
          log?.warn?.(
            `[XiotBox] SESSION.REGISTER failed conversation=${String(data.conversation_id || '')} error=${String(data.error || 'unknown')}`,
          );
        }
      });

      client.on('COMMAND', async (payload: any) => {
        let lifecycleContext: {
          bindingId: string;
          conversationId: string;
          agentId: string;
          runId: string;
          traceId: string | null;
        } | null = null;
        const emitLifecycleEvent = (
          kind: string,
          eventPayload: Record<string, unknown>,
          occurrenceId = kind,
        ) => {
          if (!lifecycleContext) return;
          eventOutbox.enqueue({
            event_id: `${lifecycleContext.runId}:${occurrenceId}`,
            binding_id: lifecycleContext.bindingId,
            conversation_id: lifecycleContext.conversationId,
            kind,
            actor: { type: 'agent', id: lifecycleContext.agentId },
            run_id: lifecycleContext.runId,
            visibility: 'user',
            trace_id: lifecycleContext.traceId,
            payload: eventPayload,
          });
        };
        try {
          const cmdId = payload?.command_id;
          if (!cmdId) return;

          const cached = getCached(cmdId);
          if (cached) {
            // Gateway redelivery: replay the exact cached terminal frame
            // (canonical ACK rejection or COMMAND_RESULT) — replay stays
            // idempotent (XIOT-BUG-0050b, PLAN-0008 §4.6).
            client.sendMessage(cached.type, cached.payload);
            return;
          }

          const traceId = payload?.trace_id || payload?.payload?.trace_id || null;

          // Structured rejection on the canonical COMMAND_ACK (PLAN-0008
          // §4.1/§4.5): protocol/security gates that fail answer
          // COMMAND_ACK {accepted:false, rejection:{class,code,detail?}}
          // before any business processing; the Gateway terminalizes `failed`
          // from this ACK in the same transaction. Classification always goes
          // through the registered exact-code table — no string prefixes.
          const rejectCommand = (code: string, detail?: string) => {
            const rejection = normalizeRuntimeError(code);
            if (detail && !rejection.detail) {
              rejection.detail = String(detail).slice(0, 512);
            }
            const frame = commandLifecycle.ackRejected(cmdId, rejection, traceId);
            if (frame) setCachedFrame(cmdId, frame.type, frame);
          };

          const incoming = payload?.payload || payload || {};

          // ── Session command dispatch (XIOT-BUG-0006) ──
          // Non-chat commands carry plain JSON and no OGE2E1 envelope; they
          // must be routed before the chat/E2E path or they fail with
          // e2e_required. command_type arrives at the bot payload top level
          // (client_ws.py flattens it next to command_id).
          const sessionCommandType = normalizeStringValue(payload?.command_type)
            ?? normalizeStringValue(incoming?.command_type)
            ?? '';
          if (sessionCommandType.startsWith('workspace.')) {
            await handleWorkspaceCommand({
              commandType: sessionCommandType,
              incoming,
              cmdId,
              traceId,
            });
            return;
          }
          const sessionAction = resolveSessionCommandAction(sessionCommandType);
          if (sessionAction !== 'chat') {
            handleSessionCommand({
              action: sessionAction,
              payload,
              incoming,
              cmdId,
              traceId,
            });
            return;
          }

          // Per-command execution gate (XIOT-BUG-0050b R1): a chat command
          // that already claimed execution (accepted/delivered, terminal
          // result still pending) must never re-enter the business path,
          // whatever the redelivered payload contains — command_id is the
          // sole idempotency key. Replay the recorded lifecycle evidence and
          // wait for the terminal result.
          if (commandLifecycle.isAccepted(cmdId)) {
            commandLifecycle.replayLifecycleEvidence(cmdId);
            return;
          }

          // Always refresh client peer key before handling a command.
          // This avoids encrypting reply with stale key after mobile/desktop key rotation.
          const cachedPeerPublicKey = e2e.peerPublicKey || '';
          const cachedPeerKeyId = e2e.peerKeyId || '';
          try {
            await e2e.refreshPeerKey();
          } catch (err: any) {
            const refreshErr = err?.message || 'e2e_peer_refresh_failed';
            // Preserve service continuity for existing sessions:
            // if a previously trusted key exists, keep using it for this command.
            if (cachedPeerPublicKey) {
              e2e.peerPublicKey = cachedPeerPublicKey;
              e2e.peerKeyId = cachedPeerKeyId;
              e2e.peerTrustError = refreshErr;
              log?.warn?.(`[XiotBox] E2E peer key refresh failed, fallback to cached key: ${refreshErr}`);
            } else {
              e2e.peerPublicKey = '';
              e2e.peerKeyId = '';
              e2e.peerTrustError = refreshErr;
            }
          }

          const env = (incoming?.magic === 'OGE2E1' ? incoming : incoming?.e2e) || null;
          if (!env || env.magic !== 'OGE2E1') {
            // Chat commands without an OGE2E1 envelope violate the declared
            // protocol. E2E stays mandatory (PLAN-0008 §5.3); classified as
            // protocol structure error (§4.5).
            rejectCommand('e2e_required');
            return;
          }

          const contentType = incoming?.content_type || incoming?.contentType || 'text/markdown';
          const threadId = normalizeThreadId(incoming?.thread_id || e2e.threadId);
          let conversationBinding = null;
          try {
            conversationBinding = resolveConversationBinding(incoming, finalCfg.DEVICE_ID);
          } catch (err) {
            rejectCommand(
              'conversation_binding_invalid',
              err instanceof Error ? err.message : 'invalid conversation binding',
            );
            return;
          }
          const contextEpochResolution = resolveInboundContextEpoch({
            incoming,
            deviceId: finalCfg.DEVICE_ID,
            threadId,
            traceId,
            messageId: cmdId,
            log,
          });
          const contextEpoch = conversationBinding?.contextEpoch ?? contextEpochResolution.epoch;
          // XIOT-BUG-0118: the reply/identity AAD must match the dispatch
          // AAD derivation — same preset segment, same canonical semantics.
          const dispatchPermissionPreset =
            typeof incoming?.permission_preset === 'string'
              ? incoming.permission_preset.trim()
              : '';
          const commandAad = e2e.buildAad({
            direction: 'c2p',
            device_id: finalCfg.DEVICE_ID,
            thread_id: threadId,
            command_id: cmdId,
            content_type: contentType,
            chunk_seq: 0,
            enc_v: Number(env?.enc_version ?? e2e.encV),
            permission_preset: dispatchPermissionPreset,
          });
          let text = '';
          try {
            text = e2e.decryptText(env, {
              direction: 'c2p',
              device_id: finalCfg.DEVICE_ID,
              thread_id: threadId,
              command_id: cmdId,
              content_type: contentType,
              chunk_seq: 0,
              enc_v: Number(env?.enc_version ?? e2e.encV),
              // XIOT-BUG-0118: the permission preset is part of the
              // authenticated dispatch context, derived from THIS frame's
              // payload field; a preset tampered, deleted or injected in
              // flight fails AAD verification with its ciphertext.
              // Absent/empty keeps the legacy byte-identical AAD.
              permission_preset: dispatchPermissionPreset,
            });
          } catch (_err: any) {
            // Envelope unparseable/undecryptable or AAD mismatch: protocol
            // structure error (PLAN-0008 §4.5) — not yet an identity verdict.
            rejectCommand('e2e_decrypt_failed');
            return;
          }

          const replyPeers = e2e.collectReplyPeers(incoming, {
            commandId: cmdId,
            canonicalAad: commandAad,
            envelope: env,
          });
          if (!replyPeers.length) {
            // Structurally valid material that fails verification / trust
            // pinning / authorization normalizes to class=policy (§4.5 row 3).
            rejectCommand(e2e.peerTrustError || 'e2e_peer_missing');
            return;
          }

          // Claim execution immediately before business entry — the last
          // gate before any side effect (XIOT-BUG-0050b R1). First caller
          // wins; a same-tick duplicate that lost the early gate replays the
          // recorded evidence inside ackAccepted and short-circuits here,
          // never re-entering the business path. The ownership stays active
          // until the terminal result is cached (setCached → markTerminal).
          if (!commandLifecycle.ackAccepted(cmdId, traceId)) {
            return;
          }
          commandLifecycle.markDelivered(cmdId);

          const buildEncryptedResult = (
            replyText: string,
            seq: number,
            sessionUsage?: SessionUsageSnapshot | null,
            streamMeta?: {
              thinking?: string;
              progress?: string;
              lane?: string;
              events?: StreamEvent[];
            },
          ) => {
            const e2eMulti: Record<string, any> = {};
            let primaryEnv: any = null;
            let primaryKeyId = '';
            for (const peer of replyPeers) {
              const envOut = e2e.encryptText(
                replyText,
                {
                  direction: 'p2c',
                  device_id: finalCfg.DEVICE_ID,
                  thread_id: threadId,
                  command_id: cmdId,
                  content_type: contentType,
                  chunk_seq: seq,
                  enc_v: e2e.encV,
                },
                {
                  publicKey: peer.publicKey,
                  keyId: peer.keyId,
                },
              );
              const envKeyId = peer.keyId || envOut?.key_id || '';
              if (!primaryEnv) {
                primaryEnv = envOut;
                primaryKeyId = envKeyId;
              }
              e2eMulti[envKeyId || `peer_${Object.keys(e2eMulti).length}`] = envOut;
            }
            const result: Record<string, any> = {
              e2e: primaryEnv,
              e2e_multi: e2eMulti,
              result_key_id: primaryKeyId,
              enc_v: e2e.encV,
              content_type: contentType,
              chunk_seq: seq,
            };
            if (streamMeta) {
              const metadata: Record<string, any> = {};
              if (typeof streamMeta.lane === 'string' && streamMeta.lane.trim()) {
                metadata.stream_lane = streamMeta.lane.trim();
              }
              if (typeof streamMeta.thinking === 'string' && streamMeta.thinking.trim()) {
                metadata.stream_thinking = streamMeta.thinking;
              }
              if (typeof streamMeta.progress === 'string' && streamMeta.progress.trim()) {
                metadata.stream_progress = streamMeta.progress;
              }
              if (Array.isArray(streamMeta.events) && streamMeta.events.length) {
                metadata.stream_events = streamMeta.events;
              }
              if (Object.keys(metadata).length) {
                result.metadata = metadata;
              }
            }
            if (sessionUsage) {
              result.session_usage = {
                total_tokens: sessionUsage.totalTokens,
                input_tokens: sessionUsage.inputTokens,
                output_tokens: sessionUsage.outputTokens,
                context_tokens: sessionUsage.contextTokens,
                total_tokens_fresh: sessionUsage.totalTokensFresh,
                updated_at: sessionUsage.updatedAt,
              };
              result.session_total_tokens = sessionUsage.totalTokens;
            }
            return result;
          };

          const senderId = payload?.from || 'xiotbox';
          const fullConfig = resolveEffectiveConfig(ctx, cfg);
          const agentId = conversationBinding?.agentId || resolveThreadAgentId(fullConfig, threadId);
          const sessionKey = conversationBinding?.sessionKey ||
            buildSessionKey(agentId, finalCfg.DEVICE_ID, threadId, contextEpoch);
          // Track conversation→session for session.* command dispatch
          // (XIOT-BUG-0006): model.select/archive arrive with conversation_id
          // only and must resolve back to the exact session.
          if (conversationBinding?.conversationId) {
            rememberConversationBinding(conversationBinding.conversationId, {
              sessionKey,
              agentId,
              contextEpoch,
            });
            // Runtime visibility (XIOT-BUG-0007): publish the bound
            // conversation to the gateway (idempotent upsert).
            sendSessionRegister({
              conversationId: conversationBinding.conversationId,
              agentId,
              contextEpoch,
            });
          }
          // 客户端随消息带上 permission（full | readonly），驱动本会话的工具策略。
          const inboundPermission = incoming?.metadata?.permission;
          if (inboundPermission === 'readonly' || inboundPermission === 'full') {
            setSessionPermission(sessionKey, inboundPermission);
          }
          // 客户端随消息带上 model（provider/model），会话级覆盖本轮模型选择。
          const inboundModel = incoming?.metadata?.model;
          if (inboundModel) {
            setSessionModelOverride(sessionKey, String(inboundModel));
          }

          // ── Message identity contract (XIOT-BUG-0005) ──
          // command_id is the sole run identity. The same text under a
          // different command_id is an independent run and must be dispatched
          // again; content-level replay is intentionally NOT performed here.
          // Exact command_id idempotency is handled by the commandCache.

          if (conversationBinding) {
            lifecycleContext = {
              bindingId: conversationBinding.bindingId,
              conversationId: conversationBinding.conversationId,
              agentId,
              runId: cmdId,
              traceId,
            };
            for (const projection of projectUserMessage(text, incoming?.metadata, cmdId)) {
              emitLifecycleEvent(
                projection.kind,
                projection.payload,
                projection.occurrenceId,
              );
            }
            emitLifecycleEvent('run.started', {
              status: 'running',
              agent_profile_id: conversationBinding.agentProfileId,
              binding_version: conversationBinding.bindingVersion,
            });
          }
          const counterKey = toolOnlyCounterKey(
            finalCfg.DEVICE_ID,
            threadId,
            senderId,
          );
          const forceExitKeyValue = forceExitKey(finalCfg.DEVICE_ID, threadId);

          log?.debug?.(JSON.stringify({
            event: 'session_scope',
            trace_id: traceId || '',
            message_id: cmdId,
            device_id: finalCfg.DEVICE_ID,
            thread_id: threadId,
            agent_id: agentId,
            context_epoch: contextEpoch,
            context_epoch_source: contextEpochResolution.source,
            session_key: sessionKey,
            conversation_id: conversationBinding?.conversationId || '',
            binding_id: conversationBinding?.bindingId || '',
            binding_version: conversationBinding?.bindingVersion || 0,
          }));

          // Periodic cleanup of stale counters
          pruneToolOnlyCounters();
          pruneForceExitCounters();

          // ── Auto-exit carry-over: enforce exit mode on next user message ──
          const shouldForceExit = consumeForceExit(forceExitKeyValue);
          if (shouldForceExit) {
            resetToolOnlyCounter(counterKey);
            log?.info?.(JSON.stringify({
              event: 'auto_exit_control_mode',
              trace_id: traceId,
              thread_id: threadId,
              message_id: cmdId,
              sender_id: senderId,
            }));
            text = `The user requested to exit control mode. Do not call any tools. Reply with text only. User message: ${text}`;
          }

          // ── Hard-exit: user explicitly wants to leave tool/control mode ──
          const hardExitRequested = !shouldForceExit && isHardExitCommand(text);
          if (hardExitRequested) {
            resetToolOnlyCounter(counterKey);
            scheduleForceExit(forceExitKeyValue);
            log?.info?.(JSON.stringify({
              event: 'hard_exit_command',
              trace_id: traceId,
              thread_id: threadId,
              message_id: cmdId,
              sender_id: senderId,
              input_text: text.slice(0, 80),
            }));
            // Hard-exit should be deterministic: do not rely on model/tool path for this turn.
            const hardExitChunkSeq = 1;
            const successPayload = {
              command_id: cmdId,
              status: 'success',
              trace_id: traceId,
              result: buildEncryptedResult(
                'Exited control mode and switched back to chat mode. Continue with text-only conversation. If control is needed again, ask with a new operation request.',
                hardExitChunkSeq,
                resolveSessionUsageSnapshot(fullConfig, sessionKey),
              ),
            };
            client.sendMessage('COMMAND_RESULT', successPayload);
            for (const projection of projectAssistantMessage(
              'Exited control mode and switched back to chat mode. Continue with text-only conversation. If control is needed again, ask with a new operation request.',
              '',
              incoming?.metadata,
              cmdId,
            )) {
              emitLifecycleEvent(
                projection.kind,
                projection.payload,
                projection.occurrenceId,
              );
            }
            emitLifecycleEvent('run.completed', {
              status: 'completed',
              mode: 'text_only_exit',
            });
            setCached(cmdId, successPayload);
            return;
          }
          const forceTextOnly = shouldForceExit || hardExitRequested;
          const stagedInlineMediaCount = stageInlineMediaPayload(incoming, {
            log,
            traceId,
            messageId: cmdId,
          });
          if (stagedInlineMediaCount > 0) {
            log?.info?.(JSON.stringify({
              event: 'inline_media_staged',
              trace_id: traceId || '',
              message_id: cmdId,
              staged_count: stagedInlineMediaCount,
            }));
          }
          const inboundMediaCtx = buildInboundMediaContext(incoming);
          if (inboundMediaCtx.MediaPaths?.length) {
            log?.debug?.(JSON.stringify({
              event: 'inbound_media_mapped',
              trace_id: traceId || '',
              message_id: cmdId,
              media_count: inboundMediaCtx.MediaPaths.length,
              media_types: inboundMediaCtx.MediaTypes || [],
            }));
          }

          const inboundCtx = {
            Body: text,
            RawBody: text,
            CommandBody: text,
            From: senderId,
            To: finalCfg.DEVICE_ID,
            SessionKey: sessionKey,
            AccountId: accountId,
            MessageSid: cmdId,
            TraceId: traceId,
            ChatType: 'direct',
            ConversationLabel: `${finalCfg.DEVICE_ID}:${threadId}`,
            XiotBoxConversationId: conversationBinding?.conversationId,
            XiotBoxAgentProfileId: conversationBinding?.agentProfileId,
            SenderId: senderId,
            CommandAuthorized: true,
            Provider: 'xiotbox',
            Surface: 'xiotbox',
            OriginatingChannel: 'xiotbox',
            OriginatingTo: conversationBinding?.conversationId || threadId,
            ...inboundMediaCtx,
            DeliveryContext: {
              channel: 'xiotbox',
              to: conversationBinding?.conversationId || threadId,
              threadId,
              contextEpoch,
              conversationId: conversationBinding?.conversationId,
              bindingId: conversationBinding?.bindingId,
              bindingVersion: conversationBinding?.bindingVersion,
            },
          };

          // OpenClaw dispatcher returns metadata and delivers actual reply payloads
          // asynchronously via `deliver(payload, { kind })`.
          let lastText = '';
          let finalText = '';
          const blockParts: string[] = [];
          let lastTextStreamAt = 0;
          let lastTextStreamText = '';
          let runningSnapshotText = '';
          let thinkingSnapshotText = '';
          let progressSnapshotText = '';
          let chunkSeq = 0;
          let lastProgressAt = 0;
          let progressUpdateCount = 0;
          let lastProgressFingerprint = '';
          let dispatchMeta: { queuedFinal?: boolean; counts?: Record<string, number> } | null = null;
          const skipEvents: Array<{ kind: string; reason: string }> = [];

          const mergeRunningSnapshot = (existingText: string, incomingText: string): string => {
            const oldText = String(existingText || '');
            const newText = String(incomingText || '');
            if (!newText) return oldText;
            if (!oldText) return newText;
            if (newText === oldText) return oldText;
            if (newText.startsWith(oldText)) return newText;
            if (oldText.startsWith(newText)) return oldText;

            // Cap overlap search to avoid O(N²) stalls on long texts
            const maxOverlap = Math.min(oldText.length, newText.length, 512);
            for (let i = maxOverlap; i >= 1; i -= 1) {
              if (oldText.slice(oldText.length - i) === newText.slice(0, i)) {
                return oldText + newText.slice(i);
              }
            }
            return oldText + newText;
          };

          const emitRunningUpdate = (
            runningText: string,
            fingerprint: string,
            opts?: {
              force?: boolean;
              toolNames?: string[];
              snapshot?: ProgressSnapshot | null;
              fallbackText?: string;
            },
          ) => {
            if (!finalCfg.PROGRESS_UPDATES) return;
            const textPayload = compactProgressText(runningText, 180);
            if (!textPayload) return;

            const now = Date.now();
            const isForce = opts?.force === true;
            if (!isForce) {
              if (progressUpdateCount >= finalCfg.PROGRESS_MAX_UPDATES) return;
              if (fingerprint && fingerprint === lastProgressFingerprint) return;
              if (now - lastProgressAt < finalCfg.PROGRESS_THROTTLE_MS) return;
            }

            progressUpdateCount += 1;
            lastProgressAt = now;
            if (fingerprint) lastProgressFingerprint = fingerprint;
            progressSnapshotText = textPayload;
            const streamEvents = buildRunningStreamEvents({
              toolNames: opts?.toolNames || toolNamesSeen,
              snapshot: opts?.snapshot || null,
              fallbackText: opts?.fallbackText || runningText,
              thinkingText: thinkingSnapshotText,
            });

            chunkSeq += 1;
            client.sendMessage('COMMAND_RESULT', {
              command_id: cmdId,
              status: 'running',
              trace_id: traceId,
              result: buildEncryptedResult(textPayload, chunkSeq, null, {
                progress: progressSnapshotText,
                thinking: thinkingSnapshotText,
                lane: 'progress',
                events: streamEvents,
              }),
            });
          };

          const emitTextSnapshot = (snapshotText: string) => {
            if (!finalCfg.STREAMING) return;
            const normalized = String(snapshotText || '');
            if (!normalized.trim()) return;

            const now = Date.now();
            if (now - lastTextStreamAt < finalCfg.STREAM_THROTTLE_MS) return;
            if (normalized === lastTextStreamText) return;

            lastTextStreamAt = now;
            lastTextStreamText = normalized;
            runningSnapshotText = normalized;
            chunkSeq += 1;
            client.sendMessage('COMMAND_RESULT', {
              command_id: cmdId,
              status: 'running',
              trace_id: traceId,
              result: buildEncryptedResult(normalized, chunkSeq, null, {
                progress: progressSnapshotText,
                thinking: thinkingSnapshotText,
                lane: 'text',
              }),
            });
          };

          // Signals to avoid "empty success"
          let sawAnyDeliver = false;
          let sawToolLikeDeliver = false;
          let sawNonTextDeliver = false;
          let sawControlToolSignal = false;
          let sawInProgressSignal = false;
          const toolNamesSeen: string[] = [];
          // Prefer block streaming from runtime reply hooks when available.
          // Fallback runtimes still stream from `deliver(kind=block)`.
          let streamBlocksViaReplyOptions = false;

          const deliver = async (outPayload: any, info?: any) => {
            const kind = info?.kind || 'block';
            sawAnyDeliver = true;

            // XiotBox's inbound dispatcher delivers agent replies directly to
            // COMMAND_RESULT, bypassing the standard channel outbound adapter.
            // Observe approval and ask_user payloads here while the conversation
            // binding is still active; the outbound hook remains as an
            // idempotent fallback for delayed/core-initiated deliveries.
            handleOutboundApprovalPayload({
              accountId,
              payload: outPayload,
              conversationId: conversationBinding?.conversationId || threadId,
            });
            handleOutboundAskUserPayload({
              accountId,
              payload: outPayload,
              conversationId: conversationBinding?.conversationId || threadId,
            });

            const isToolKind = kind === 'tool';
            const hasTool = isToolKind || detectToolSignals(outPayload);
            if (hasTool) {
              sawToolLikeDeliver = true;
              // Collect tool names for summary
              const toolNames = extractToolSignalNames(outPayload);
              // When kind=tool, the dispatcher sends tool summary text.
              // Try to extract tool name from the summary text if no structured names found.
              if (isToolKind && !toolNames.length) {
                const summaryText = normalizeTextPayload(outPayload);
                if (summaryText) {
                  const toolNameMatch = summaryText.match(/^(?:#+\s*)?(\S+)/);
                  if (toolNameMatch) {
                    toolNames.push(toolNameMatch[1].replace(/[:`]/g, ''));
                  }
                }
              }
              if (toolNames.length) {
                toolNamesSeen.push(...toolNames);
                if (toolNames.some((name) => isLikelyControlToolName(name))) {
                  sawControlToolSignal = true;
                }
              }
            }
            const payloadInProgressSignal = hasInProgressSignal(outPayload);
            if (payloadInProgressSignal) {
              sawInProgressSignal = true;
            }

            const replyText = normalizeTextPayload(outPayload);
            const replyLooksInProgress = Boolean(replyText && isLikelyInProgressText(replyText));
            if (replyLooksInProgress) {
              sawInProgressSignal = true;
            }
            const progressSnapshot = extractProgressSnapshot(outPayload);
            const shouldEmitProgressUpdate =
              kind !== 'final' &&
              (hasTool || payloadInProgressSignal || progressSnapshot != null || replyLooksInProgress) &&
              (!replyText || replyLooksInProgress || isToolKind);
            if (shouldEmitProgressUpdate) {
              emitRunningUpdate(
                buildProgressRunningText({
                  toolNames: toolNamesSeen,
                  snapshot: progressSnapshot,
                  fallbackText: replyText,
                }),
                buildProgressFingerprint({
                  kind,
                  toolNames: toolNamesSeen,
                  snapshot: progressSnapshot,
                  fallbackText: replyText,
                }),
                {
                  toolNames: toolNamesSeen.slice(),
                  snapshot: progressSnapshot,
                  fallbackText: replyText,
                },
              );
            }

            const keysPresent =
              outPayload && typeof outPayload === 'object'
                ? Object.keys(outPayload).sort()
                : [String(typeof outPayload)];

            log?.debug?.(JSON.stringify({
              event: 'deliver',
              trace_id: traceId || '',
              message_id: cmdId,
              kind,
              text_len: replyText.length,
              has_tool: hasTool,
              keys: keysPresent,
              tool_names: summarizeToolSignals(outPayload),
              control_tool_signal: sawControlToolSignal,
              in_progress_signal: sawInProgressSignal,
            }));

            if (!replyText) {
              sawNonTextDeliver = true;
              // Internal event / tool call / observation with no human text.
              // Do not emit as chat bubble.
              return;
            }

            lastText = replyText;
            if (kind === 'block') {
            // Always append block content to blockParts so the final text stays complete.
            // onBlockReply may not fire for non-streaming responses, which would otherwise leave blockParts empty.
              blockParts.push(replyText);
            } else if (kind === 'final') {
              finalText = replyText;
            }

            if (!finalCfg.STREAMING) return;

            // Only stream block replies to avoid leaking tool payloads to the chat UI.
            if (kind !== 'block') return;
            // When runtime reply hooks are available, onBlockReply is the single
            // source of body streaming. Avoid double-sending the same block
            // snapshots via both deliver() and onBlockReply().
            if (streamBlocksViaReplyOptions) return;

            const blockSnapshotText = mergeRunningSnapshot(
              runningSnapshotText,
              blockParts.join('\n'),
            );
            emitTextSnapshot(blockSnapshotText);
          };

          const effectiveConfig = forceTextOnly ? buildTextOnlyConfig(fullConfig) : fullConfig;

          emitRunningUpdate('Instruction received, running…', 'phase:accepted', { force: true });

          // Prefer deterministic dispatch path that waits for all queued deliveries before finalizing.
          const createDispatcher = replyApi?.createReplyDispatcherWithTyping;
          const finalizeCtx = replyApi?.finalizeInboundContext;
          const dispatchFromConfig = replyApi?.dispatchReplyFromConfig;

          const unregisterToolRun = conversationBinding
            ? registerActiveToolRun({ sessionKey, agentId, emit: emitLifecycleEvent })
            : () => {};
          const unregisterSubagentParent = conversationBinding && lifecycleContext
            ? registerActiveSubagentParent({
                deviceId: finalCfg.DEVICE_ID,
                sessionKey,
                bindingId: lifecycleContext.bindingId,
                conversationId: lifecycleContext.conversationId,
                threadId,
                agentId,
                parentRunId: lifecycleContext.runId,
                traceId: lifecycleContext.traceId,
              })
            : () => {};
          const unregisterApprovalBinding = conversationBinding && lifecycleContext
            ? registerActiveApprovalBinding({
                accountId,
                deviceId: finalCfg.DEVICE_ID,
                sessionKey,
                bindingId: lifecycleContext.bindingId,
                conversationId: lifecycleContext.conversationId,
                agentId,
                runId: lifecycleContext.runId,
                traceId: lifecycleContext.traceId,
              })
            : () => {};
          const unregisterAskUserBinding = conversationBinding && lifecycleContext
            ? registerActiveAskUserBinding({
                accountId,
                deviceId: finalCfg.DEVICE_ID,
                sessionKey,
                bindingId: lifecycleContext.bindingId,
                conversationId: lifecycleContext.conversationId,
                agentId,
                runId: lifecycleContext.runId,
                traceId: lifecycleContext.traceId,
              })
            : () => {};
          const unregisterMemoryBinding = conversationBinding && lifecycleContext
            ? registerActiveMemoryBinding({
                accountId,
                deviceId: finalCfg.DEVICE_ID,
                sessionKey,
                bindingId: lifecycleContext.bindingId,
                conversationId: lifecycleContext.conversationId,
                agentId,
                runId: lifecycleContext.runId,
                traceId: lifecycleContext.traceId,
              })
            : () => {};
          try {
          if (createDispatcher && finalizeCtx && dispatchFromConfig) {
            streamBlocksViaReplyOptions = true;
            const { dispatcher, replyOptions, markDispatchIdle } = createDispatcher({
              deliver,
              onSkip: (_payload: any, info: any) => {
                skipEvents.push({
                  kind: String(info?.kind || 'unknown'),
                  reason: String(info?.reason || 'unknown'),
                });
              },
              onError: (err: any, info: any) => {
                log?.warn?.(
                  `[XiotBox] OpenClaw deliver error kind=${info?.kind || 'unknown'} err=${err?.message || err}`,
                );
              },
            });

            const runtimeReplyOptions = {
              ...replyOptions,
              disableBlockStreaming:
                typeof finalCfg.BLOCK_STREAMING === 'boolean'
                  ? !finalCfg.BLOCK_STREAMING
                  : undefined,
              onBlockReply: (payload: any) => {
                try {
                  // ask_user 问题走 block-reply 面，先投影（与 STREAMING 无关）。
                  handleOutboundAskUserPayload({
                    accountId,
                    payload,
                    conversationId: conversationBinding?.conversationId || threadId,
                  });
                  if (!finalCfg.STREAMING) return;
                  const blockText =
                    typeof payload === 'string'
                      ? payload
                      : payload?.text || normalizeTextPayload(payload);
                  if (!blockText) return;
                  log?.debug?.(JSON.stringify({
                    event: 'onBlockReply',
                    trace_id: traceId || '',
                    text_len: blockText.length,
                    text_preview: blockText.slice(0, 60),
                  }));
              // Skip when deliver() already pushed the same block to avoid duplicates.
                  if (!blockParts.includes(blockText)) {
                    blockParts.push(blockText);
                  }
                  const blockSnapshotText = mergeRunningSnapshot(
                    runningSnapshotText,
                    blockParts.join('\n'),
                  );
                  emitTextSnapshot(blockSnapshotText);
                } catch (err) {
                  log?.error?.(`[XiotBox][${accountId}] onBlockReply error: ${err instanceof Error ? err.message : String(err)}`);
                }
              },
              onReasoningStream: (payload: any) => {
                try {
                  const reasoningText =
                    typeof payload === 'string'
                      ? payload
                      : payload?.text || payload?.thinking || normalizeReasoningPayload(payload);
                  if (!reasoningText) return;
                  thinkingSnapshotText = mergeRunningSnapshot(
                    thinkingSnapshotText,
                    reasoningText,
                  );
                } catch (err) {
                  log?.error?.(`[XiotBox][${accountId}] onReasoningStream error: ${err instanceof Error ? err.message : String(err)}`);
                }
              },
              onPartialReply: (payload: any) => {
                try {
                  const reasoningText = normalizeReasoningPayload(payload);
                  if (reasoningText) {
                    thinkingSnapshotText = mergeRunningSnapshot(
                      thinkingSnapshotText,
                      reasoningText,
                    );
                  }
                } catch (err) {
                  log?.error?.(`[XiotBox][${accountId}] onPartialReply error: ${err instanceof Error ? err.message : String(err)}`);
                }
              },
            };

            const finalized = finalizeCtx(inboundCtx);
            dispatchMeta = await dispatchFromConfig({
              ctx: finalized,
              cfg: effectiveConfig,
              dispatcher,
              replyResolver: null,
              replyOptions: runtimeReplyOptions,
            });

            await dispatcher.waitForIdle();
            markDispatchIdle();
          } else {
            // Fallback for older runtimes.
            const { queuedFinal, counts } = await dispatchReply({
              ctx: inboundCtx,
              cfg: effectiveConfig,
              replyResolver: null,
              dispatcherOptions: {
                deliver,
              },
            });
            dispatchMeta = { queuedFinal, counts };
            // Let queued microtasks flush `deliver()` at least once before we finalize.
            await Promise.resolve();
          }
          } finally {
            unregisterApprovalBinding();
            unregisterAskUserBinding();
            unregisterMemoryBinding();
            unregisterSubagentParent();
            unregisterToolRun();
          }

          // Prefer finalText, then blocks (joined with newline), then lastText
          const blocksText = blockParts.join('\n');
          let resolvedFinalText = (finalText || blocksText || lastText || '').trim();

          // Determine if this reply is tool-only (no human text produced)
          const toolOnlyLikely = sawToolLikeDeliver || sawNonTextDeliver;
          const isToolOnlyReply = !resolvedFinalText && toolOnlyLikely;
          const isNoReply = resolvedFinalText ? shouldSkipReply(resolvedFinalText) : false;
          // When a control tool (xiotbox_control etc.) ran, the agent's short ack
          // ("operation completed", "done", etc.) IS the meaningful reply - do not replace it.
          const isAckOnlyReply = resolvedFinalText && !sawControlToolSignal
            ? isLikelyNonSubstantiveAck(resolvedFinalText)
            : false;
          const needsFallback = isToolOnlyReply || isNoReply || !resolvedFinalText || isAckOnlyReply;
          const shouldCountFallback = needsFallback && !sawInProgressSignal;
          const fallbackBranch: 'tool_only' | 'no_reply' | 'ack_only' | 'empty' = isToolOnlyReply
            ? 'tool_only'
            : isNoReply
              ? 'no_reply'
              : isAckOnlyReply
                ? 'ack_only'
                : 'empty';

          // ── Structured log helper ──
          const structuredLog = (level: 'debug' | 'info' | 'warn', event: string, extra?: Record<string, any>) => {
            const entry = {
              event,
              trace_id: traceId || '',
              thread_id: threadId || '',
              context_epoch: contextEpoch,
              session_key: sessionKey,
              message_id: cmdId,
              branch: needsFallback ? fallbackBranch : 'normal',
              should_count_fallback: shouldCountFallback,
              saw_control_tool_signal: sawControlToolSignal,
              saw_in_progress_signal: sawInProgressSignal,
              resolved_text_len: resolvedFinalText.length,
              tool_names: toolNamesSeen.slice(),
              ...extra,
            };
            log?.[level]?.(JSON.stringify(entry));
          };

          // Build a dynamic summary when only tool calls were executed (no human text).
          const buildToolSummary = (opts?: { inProgress?: boolean }): string => {
            const uniq = Array.from(new Set(toolNamesSeen.map(s => s.trim()).filter(Boolean)));
            if (opts?.inProgress) {
              if (uniq.length) {
                return `(Running: ${uniq.join(', ')})`;
              }
              return '(Running operation, please wait)';
            }
            if (uniq.length) {
              return `(Executed: ${uniq.join(', ')})`;
            }
            return '(Operation completed)';
          };

          if (!resolvedFinalText) {
            // If OpenClaw queued something but we got no text, treat as failure (bug/merge issue).
            const queuedFinal = Boolean(dispatchMeta?.queuedFinal || (dispatchMeta?.counts?.final || 0) > 0);

            if (queuedFinal && !toolOnlyLikely) {
              const failPayload = {
                command_id: cmdId,
                status: 'failed',
                trace_id: traceId,
                error: 'empty_reply_from_openclaw',
                result: {},
              };
              structuredLog('warn', 'empty_reply_queued_final', {
                dispatch_meta: dispatchMeta,
                skip_events: skipEvents,
                saw_any_deliver: sawAnyDeliver,
              });
              client.sendMessage('COMMAND_RESULT', failPayload);
              setCached(cmdId, failPayload);
              return;
            }

            resolvedFinalText = buildToolSummary({
              inProgress: sawInProgressSignal,
            });
            structuredLog('info', 'tool_only_summary', {
              dispatch_meta: dispatchMeta,
              saw_any_deliver: sawAnyDeliver,
            });
          }

          // If explicitly asked for NO_REPLY semantics, still avoid empty bubble.
          if (shouldSkipReply(resolvedFinalText)) {
            resolvedFinalText = buildToolSummary({
              inProgress: sawInProgressSignal,
            });
            structuredLog('info', 'no_reply_to_summary');
          }

          // Ack-like final text is low-information for end users.
          // If tools were actually executed, show a concise tool summary instead.
          if (
            resolvedFinalText &&
            isLikelyNonSubstantiveAck(resolvedFinalText) &&
            toolNamesSeen.length > 0
          ) {
            resolvedFinalText = buildToolSummary();
            structuredLog('info', 'ack_only_to_tool_summary');
          }

          // ── Consecutive tool-only counter: auto-fallback after MAX_CONSECUTIVE_TOOL_ONLY ──
          if (shouldCountFallback) {
            const fallbackFingerprint = buildToolOnlyFingerprint({
              branch: fallbackBranch,
              text: resolvedFinalText,
              toolNames: toolNamesSeen,
              sawControlToolSignal,
              sawInProgressSignal,
            });
            const consecutiveCount = incrementToolOnlyCounter(counterKey, fallbackFingerprint);
            if (consecutiveCount >= MAX_CONSECUTIVE_TOOL_ONLY) {
              resetToolOnlyCounter(counterKey);
              scheduleForceExit(forceExitKeyValue);
              resolvedFinalText =
                buildToolSummary() +
                '\n\nWARNING: Multiple consecutive tool-only turns produced no textual reply. The plugin has automatically restored normal chat mode. If you want to continue controlling the device, send a new control request.';
              structuredLog('warn', 'consecutive_tool_only_auto_reset', {
                consecutive_count: consecutiveCount,
              });
            } else {
              structuredLog('debug', 'consecutive_tool_only_tick', {
                consecutive_count: consecutiveCount,
                fallback_fingerprint: fallbackFingerprint,
              });
            }
          } else if (needsFallback) {
            resetToolOnlyCounter(counterKey);
            structuredLog('info', 'fallback_counter_suppressed_in_progress');
          } else {
            // Normal text reply — reset the counter
            resetToolOnlyCounter(counterKey);
          }

          // Final success payload
          const sessionUsageSnapshot = resolveSessionUsageSnapshot(fullConfig, sessionKey);
          if (sessionUsageSnapshot) {
            structuredLog('debug', 'session_usage_snapshot', {
              session_total_tokens: sessionUsageSnapshot.totalTokens,
              session_input_tokens: sessionUsageSnapshot.inputTokens,
              session_output_tokens: sessionUsageSnapshot.outputTokens,
            });
          }

          chunkSeq += 1;
          structuredLog('debug', 'final_payload', {
            thinking_len: thinkingSnapshotText.length,
            thinking_preview: thinkingSnapshotText.slice(0, 120),
            text_len: resolvedFinalText.length,
          });
          const successPayload = {
            command_id: cmdId,
            status: 'success',
            trace_id: traceId,
            result: buildEncryptedResult(resolvedFinalText, chunkSeq, sessionUsageSnapshot, {
              thinking: thinkingSnapshotText,
              lane: 'final',
            }),
          };
          client.sendMessage('COMMAND_RESULT', successPayload);
          for (const projection of projectAssistantMessage(
            resolvedFinalText,
            thinkingSnapshotText,
            incoming?.metadata,
            cmdId,
          )) {
            emitLifecycleEvent(
              projection.kind,
              projection.payload,
              projection.occurrenceId,
            );
          }
          emitLifecycleEvent('run.completed', {
            status: 'completed',
            session_usage: sessionUsageSnapshot || undefined,
          });
          setCached(cmdId, successPayload);
        } catch (err: any) {
          log?.error?.(JSON.stringify({
            event: 'command_handler_error',
            account_id: accountId,
            message: err?.message || String(err),
            stack_preview: err?.stack?.split('\n').slice(0, 3).join(' '),
          }));
          const cmdId = payload?.command_id;
          const traceId = payload?.trace_id || payload?.payload?.trace_id || null;
          if (!cmdId) return;
          const failPayload = {
            command_id: cmdId,
            status: 'failed',
            trace_id: traceId,
            error: err?.message || 'Execution failed',
            result: {},
          };
          client.sendMessage('COMMAND_RESULT', failPayload);
          emitLifecycleEvent('run.failed', {
            status: 'failed',
            error_code: 'execution_failed',
          });
          setCached(cmdId, failPayload);
        }
      });

      client.on('CONTROL', async (payload: any) => {
        // This plugin is a XiotBox chat channel. Control commands are meant for XiotBox Control agents (phones),
        // not for the OpenClaw bot. Fail fast so the server doesn't keep retrying a mismatched delivery.
        try {
          const cmdId = payload?.command_id;
          if (!cmdId) return;
          const traceId = payload?.trace_id || payload?.payload?.trace_id || null;
          const failPayload = {
            command_id: cmdId,
            status: 'failed',
            trace_id: traceId,
            error: 'CONTROL_NOT_SUPPORTED_ON_BOT',
            result: {},
          };
          client.sendMessage('COMMAND_RESULT', failPayload);
          setCached(cmdId, failPayload);
        } catch (_err) {
          // ignore
        }
      });

      client.on('connected', () => {
        log?.info?.(`[XiotBox][${accountId}] Connected to Gateway`);
        setConnectedAt(accountId, instanceId, Date.now());
        updateGatewayStatus(ctx, accountId, {
          running: true,
          connected: true,
          lastConnectedAt: Date.now(),
          lastStatusAt: Date.now(),
          detail: 'connected',
        }, log);
        e2e.refreshPeerKey().catch((err: any) => {
          log?.warn?.(`[XiotBox][${accountId}] E2E peer key refresh failed: ${err?.message || err}`);
        });
        // Runtime visibility (XIOT-BUG-0007): publish the openclaw runtime so
        // /v2/runtimes and orchestrator dispatch see this device as openclaw.
        client.sendMessage('RUNTIMES.LIST', buildOpenclawRuntimeListPayload(finalCfg.DEVICE_ID, cfg));
        // Re-register known conversation bindings after a reconnect; the
        // gateway upsert is idempotent and never clobbers client bindings.
        for (const [conversationId, known] of conversationBindingRegistry.entries()) {
          sessionRegisterSent.delete(conversationId);
          sendSessionRegister({
            conversationId,
            agentId: known.agentId,
            contextEpoch: known.contextEpoch,
          });
        }
        eventOutbox.flushDue(true);
      });

      client.on('V2.EVENT_ACK', (ack: any) => {
        eventOutbox.acknowledge(ack || {});
      });

      client.on('V2.APPROVAL_RESOLVE', async (request: any) => {
        const result = await handleGatewayApprovalResolve({
          accountId,
          request,
          cfg: resolveEffectiveConfig(ctx, cfg),
          sendAck: (ack) => client.sendMessage('V2.APPROVAL_ACK', ack),
        });
        if (!result.ok) {
          log?.warn?.(
            `[XiotBox][${accountId}] approval resolve failed request_id=${String(request?.request_id || '').trim()} error=${result.error}`,
          );
        }
      });

      client.on('V2.ASK_USER_ANSWER', async (request: any) => {
        const result = await handleGatewayAskUserResolve({
          accountId,
          request,
          cfg: resolveEffectiveConfig(ctx, cfg),
          sendAck: (ack) => client.sendMessage('V2.ASK_USER_ACK', ack),
        });
        if (!result.ok) {
          log?.warn?.(
            `[XiotBox][${accountId}] ask_user resolve failed request_id=${String(request?.request_id || '').trim()} error=${result.error}`,
          );
        }
      });

      client.on('V2.AGENT_PROFILE_SYNC', async (request: any) => {
        log?.info?.(`[XiotBox][${accountId}] AGENT_PROFILE_SYNC received: ${JSON.stringify(request || {}).slice(0, 300)}`);
        await handleAgentProfileSync({
          request,
          sendAck: (ack) => {
            log?.info?.(`[XiotBox][${accountId}] AGENT_PROFILE_SYNC ack: ${JSON.stringify(ack || {}).slice(0, 300)}`);
            client.sendMessage('V2.AGENT_PROFILE_SYNC_ACK', ack);
          },
        });
      });

      client.on('disconnected', () => {
        log?.warn?.(`[XiotBox][${accountId}] Disconnected from Gateway`);
        clearConnectedAt(accountId, instanceId);
        updateGatewayStatus(ctx, accountId, {
          running: true,
          connected: false,
          lastDisconnectedAt: Date.now(),
          lastStatusAt: Date.now(),
          detail: 'disconnected',
        }, log);
      });

      client.on('error', (err: any) => {
        log?.error?.(`[XiotBox][${accountId}] Client error: ${err.message}`);
        clearConnectedAt(accountId, instanceId);
        updateGatewayStatus(ctx, accountId, {
          running: true,
          connected: false,
          lastStatusAt: Date.now(),
          detail: 'client_error',
          error: err?.message || String(err),
        }, log);
      });

      client.on('auth_required', (payload: any) => {
        log?.error?.(
          `[XiotBox][${accountId}] Gateway auth required (remote channel paused): ${payload?.message || payload?.code || 'REAUTH_REQUIRED'}`,
        );
      });

      eventOutbox.start();

      if (!isCurrentInstance()) {
        await client.disconnect();
        throw new Error(`gateway_instance_superseded_before_connect:${instanceId}`);
      }
      if (abortSignal?.aborted) {
        await stopCurrent('aborted_before_connect');
        return;
      }

      try {
        await client.connect();
      } catch (err) {
        if (isCurrentInstance()) {
          removeGatewayAccount(accountId, instanceId);
        }
        updateGatewayStatus(ctx, accountId, {
          running: false,
          connected: false,
          lastStatusAt: Date.now(),
          detail: 'connect_failed',
          error: err instanceof Error ? err.message : String(err),
        }, log);
        throw err;
      }

      if (!isCurrentInstance()) {
        await client.disconnect();
        throw new Error(`gateway_instance_superseded_after_connect:${instanceId}`);
      }
      if (abortSignal?.aborted) {
        await stopCurrent('aborted_after_connect');
        return;
      }

      // Keep the channel task alive until OpenClaw explicitly aborts it.
      // Resolving startAccount() immediately makes the host treat the channel
      // as exited, which triggers the gateway auto-restart loop.
      await waitForAbortSignal(abortSignal);
      await stopCurrent('abort_signal');
    },
    stopAccount: async (ctx: GatewayStartContextLike) => {
      const accountId = normalizeAccountId(ctx?.accountId);
      await stopGatewayAccount(accountId, 'stop_account');
      updateGatewayStatus(ctx, accountId, {
        running: false,
        connected: false,
        lastDisconnectedAt: Date.now(),
        lastStatusAt: Date.now(),
        detail: 'stop_account',
      }, ctx?.log);
    },
  },
  status: {
    probe: async ({ cfg }: any) => {
      const channelCfg = getChannelConfig(cfg);
      if (channelCfg.DEVICE_ID) {
        return { ok: true };
      }
      return { ok: false, error: 'Not configured' };
    },
  },
};
