import WebSocket from 'ws';
import { EventEmitter } from 'events';
import os from 'os';
import { createRequire } from 'module';
import path from 'path';
import { fileURLToPath } from 'url';
const require = createRequire(import.meta.url);
const moduleDir = path.dirname(fileURLToPath(import.meta.url));
const packageCandidates = path.basename(moduleDir) === 'dist'
    ? [path.join(moduleDir, '..', 'package.json'), path.join(moduleDir, 'package.json')]
    : [path.join(moduleDir, 'package.json'), path.join(moduleDir, '..', 'package.json')];
let pkg = { version: '0.0.0' };
for (const candidate of packageCandidates) {
    try {
        pkg = require(candidate);
        break;
    }
    catch (err) {
        // Try the next package metadata location.
    }
}
/**
 * WSS client.
 * Manages the WebSocket connection to XiotBox Gateway.
 */
class WSSClient extends EventEmitter {
    constructor(config) {
        super();
        this.config = config;
        this.ws = null;
        this.seq = 0; // Message sequence number
        this.reconnectDelay = 1000; // Initial reconnect delay: 1 second
        this.maxReconnectDelay = 60000; // Max reconnect delay: 60 seconds
        this.heartbeatInterval = null;
        this.isManualDisconnect = false; // Whether the disconnect was intentional
        this.outbox = [];
        this.maxOutbox = config.OUTBOX_MAX || 200;
        this.outboxTtlMs = config.OUTBOX_TTL_MS || 5 * 60 * 1000;
        this.helloExtra = config.HELLO_EXTRA || {};
        this.reconnectTimer = null;
        this.connectPromise = null;
        this.socketEpoch = 0;
        // Default to chat only. Control scope should be enabled on the device that executes
        // control actions (for example XiotBox Android Control Agent), not on the host OpenClaw.
        this.scopes = Array.isArray(config.SCOPES) ? config.SCOPES : ['chat'];
        this.controlActions = Array.isArray(config.CONTROL_ACTIONS) ? config.CONTROL_ACTIONS : [];
        this.parseWarnWindowMs = 10000;
        this.parseWarnSuppressed = 0;
        this.lastParseWarnAt = 0;
    }
    /**
     * Connect to the Gateway.
     */
    async connect() {
        if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) {
            return Promise.resolve();
        }
        if (this.connectPromise) {
            return this.connectPromise;
        }
        this.isManualDisconnect = false;
        this._clearReconnectTimer();
        const connectEpoch = ++this.socketEpoch;
        this.connectPromise = new Promise((resolve, reject) => {
            let settled = false;
            const finishResolve = () => {
                if (settled)
                    return;
                settled = true;
                resolve();
            };
            const finishReject = (err) => {
                if (settled)
                    return;
                settled = true;
                reject(err);
            };
            // Build the WSS URL, optionally including device credentials.
            const url = this._buildWsUrl();
            console.log('[WSS] Connecting to gateway...');
            const ws = new WebSocket(url, {
                headers: {
                    'User-Agent': `openclaw-xiotbox/${pkg.version}`,
                    ...(this.config.DEVICE_TOKEN ? { Authorization: `Bearer ${this.config.DEVICE_TOKEN}` } : {}),
                    ...(this.config.DEVICE_ID ? { 'X-Device-Id': this.config.DEVICE_ID } : {}),
                    ...(this.scopes.length ? { 'X-OpenClaw-Scopes': this.scopes.join(',') } : {}),
                },
            });
            this.ws = ws;
            // Connection opened
            ws.on('open', () => {
                if (this.ws !== ws || connectEpoch !== this.socketEpoch) {
                    try {
                        ws.close(1000, 'superseded');
                    }
                    catch (err) { }
                    finishResolve();
                    return;
                }
                console.log('[WSS] Connection established');
                this.reconnectDelay = 1000; // Reset backoff delay
                this.emit('connected');
                // Send HELLO with device/runtime metadata.
                this.sendHello();
                // Start heartbeat loop.
                this.startHeartbeat();
                // Flush messages buffered while offline.
                this.flushOutbox();
                finishResolve();
            });
            // Incoming message frames
            ws.on('message', (data, isBinary) => {
                if (this.ws !== ws || connectEpoch !== this.socketEpoch)
                    return;
                this._onRawMessage(data, isBinary);
            });
            // Connection closed
            ws.on('close', (code, reason) => {
                const isCurrent = this.ws === ws && connectEpoch === this.socketEpoch;
                console.log(`[WSS] Connection closed (code: ${code}, reason: ${reason || 'none'})`);
                this.emit('disconnected');
                if (isCurrent) {
                    this.stopHeartbeat();
                    this.ws = null;
                }
                if (!settled) {
                    finishReject(new Error(`WebSocket closed before ready (code=${code})`));
                }
                // Auto-reconnect unless the disconnect was intentional.
                if (!this.isManualDisconnect && isCurrent) {
                    this.scheduleReconnect();
                }
            });
            // Connection error
            ws.on('error', (err) => {
                console.error('[WSS] Connection error:', err.message);
                this.emit('error', err);
                if (this.ws !== ws || connectEpoch !== this.socketEpoch)
                    return;
                // Reject the connect promise if the socket is still connecting.
                if (ws.readyState === WebSocket.CONNECTING) {
                    finishReject(err);
                }
            });
        }).finally(() => {
            if (this.connectPromise) {
                this.connectPromise = null;
            }
        });
        return this.connectPromise;
    }
    /**
     * Disconnect manually.
     */
    async disconnect() {
        this.isManualDisconnect = true;
        this._clearReconnectTimer();
        this.stopHeartbeat();
        if (this.ws) {
            this.ws.close(1000, 'Manual disconnect');
        }
    }
    /**
     * Schedule reconnect with exponential backoff and jitter.
     */
    scheduleReconnect() {
        if (this.isManualDisconnect)
            return;
        if (this.reconnectTimer)
            return;
        if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) {
            return;
        }
        // Exponential backoff + jitter to avoid reconnect storms.
        const jitter = Math.random() * 1000;
        const delay = Math.min(this.reconnectDelay + jitter, this.maxReconnectDelay);
        console.log(`[WSS] Reconnecting in ${Math.round(delay / 1000)}s...`);
        this.reconnectTimer = setTimeout(() => {
            this.reconnectTimer = null;
            this.connect().catch((err) => {
                console.error('[WSS] Reconnect failed:', err.message);
            });
        }, delay);
        // Exponential growth: 1s -> 2s -> 4s -> 8s -> ... -> 60s
        this.reconnectDelay = Math.min(this.reconnectDelay * 2, this.maxReconnectDelay);
    }
    _clearReconnectTimer() {
        if (!this.reconnectTimer)
            return;
        clearTimeout(this.reconnectTimer);
        this.reconnectTimer = null;
    }
    /**
     * Send the HELLO message with device/runtime metadata.
     */
    sendHello() {
        const payload = {
            version: pkg.version,
            capabilities: {
                commands: ['help', 'status', 'ping', 'version'],
                streaming: false, // Streaming output is not supported here
                max_command_length: 10000,
                control_actions: this.controlActions,
                scopes: this.scopes,
            },
            runtime: {
                platform: process.platform,
                arch: process.arch,
                node_version: process.version,
                hostname: os.hostname(),
            },
        };
        // Merge so late-bound config.HELLO_EXTRA still works even if helloExtra was
        // initialized as an empty object at construction time.
        const extra = { ...(this.config?.HELLO_EXTRA || {}), ...(this.helloExtra || {}) };
        if (extra.thread_id) {
            payload.thread_id = extra.thread_id;
        }
        if (extra.e2e) {
            payload.e2e = extra.e2e;
        }
        this.sendMessage('HELLO', payload);
        console.log('[WSS] Sent HELLO');
    }
    setHelloExtra(extra) {
        this.helloExtra = extra || {};
    }
    /**
     * Start heartbeat loop (15 second interval).
     */
    startHeartbeat() {
        this.heartbeatInterval = setInterval(() => {
            this.sendMessage('HEARTBEAT', {
                // Keep plugin_version fresh on the server even when there is no reconnect/HELLO.
                version: pkg.version,
                runtime: {
                    platform: process.platform,
                    arch: process.arch,
                    node_version: process.version,
                    hostname: os.hostname(),
                },
                uptime: process.uptime(),
                memory: process.memoryUsage(),
                cpu: process.cpuUsage(),
            });
        }, 15000); // 15 second heartbeat
    }
    /**
     * Stop heartbeat loop.
     */
    stopHeartbeat() {
        if (this.heartbeatInterval) {
            clearInterval(this.heartbeatInterval);
            this.heartbeatInterval = null;
        }
    }
    /**
     * Send a message in the shared envelope format.
     */
    sendMessage(type, payload) {
        const envelope = {
            id: `msg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
            type,
            ts: Date.now(),
            device_id: this.config.DEVICE_ID,
            seq: ++this.seq,
            trace_id: payload.trace_id || null,
            payload,
        };
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify(envelope));
        }
        else {
            // Buffer the message and send it after reconnect.
            this._enqueue(envelope);
            console.warn(`[WSS] Cannot send message: connection not open (state: ${this.ws ? this.ws.readyState : 'null'})`);
        }
    }
    /**
     * Handle a decoded inbound message.
     */
    handleMessage(msg) {
        const { type, payload } = msg;
        switch (type) {
            case 'HELLO_ACK':
                // Server-side capability / handshake acknowledgements are optional today,
                // but keeping them explicit lets future gateway negotiation evolve quietly.
                this.emit('HELLO_ACK', payload);
                break;
            case 'HEARTBEAT_ACK':
                // Heartbeat response: ignore silently.
                break;
            case 'COMMAND':
                // Forward command events to the channel layer.
                this.emit('COMMAND', payload);
                break;
            case 'CONTROL':
                this.emit('CONTROL', payload);
                break;
            case 'V2.EVENT_ACK':
                this.emit('V2.EVENT_ACK', payload);
                break;
            case 'V2.APPROVAL_RESOLVE':
                this.emit('V2.APPROVAL_RESOLVE', payload);
                break;
            case 'V2.ASK_USER_ANSWER':
                this.emit('V2.ASK_USER_ANSWER', payload);
                break;
            case 'V2.AGENT_PROFILE_SYNC':
                // Gateway asks the channel to materialize a main agent as
                // agents.entries.<agent_id>; channel.ts listens for this event.
                this.emit('V2.AGENT_PROFILE_SYNC', payload);
                break;
            case 'SESSION.ARCHIVE_ACK':
                // Gateway acknowledges a SESSION.ARCHIVE round-trip; channel.ts
                // settles the pending session.archive COMMAND_RESULT with it.
                this.emit('SESSION.ARCHIVE_ACK', payload);
                break;
            case 'SESSION.REGISTER_ACK':
                // Gateway acknowledges a SESSION.REGISTER upsert; channel.ts
                // logs failures for observability only.
                this.emit('SESSION.REGISTER_ACK', payload);
                break;
            case 'RUNTIMES.REQUEST':
                // XIOT-BUG-0221: the gateway asks this Runtime to re-declare its
                // registry. Without this case the frame falls through to the
                // "Unknown message type" default and channel.ts never learns
                // about it — the same two-layer trap as V2.APPROVAL_RESOLVE.
                this.emit('RUNTIMES.REQUEST', payload);
                break;
            case 'ERROR':
                console.error('[WSS] Server error:', payload);
                if (payload.code === 'REAUTH_REQUIRED') {
                    console.error('[WSS] Token invalid or revoked, remote channel will pause until reconfigured');
                    // Do not terminate the whole OpenClaw gateway process.
                    // Remote XiotBox channel auth failure must not break local gateway APIs.
                    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
                        this.ws.close(4001, 'XiotBox reauth required');
                    }
                    this.emit('auth_required', payload);
                }
                break;
            default:
                console.warn('[WSS] Unknown message type:', type);
        }
    }
    _onRawMessage(data, isBinary = false) {
        const text = this._extractJsonText(data, isBinary);
        if (!text)
            return;
        try {
            const msg = JSON.parse(text);
            if (!msg || typeof msg !== 'object') {
                this._warnParseIssue('non-object JSON payload', text);
                return;
            }
            this.handleMessage(msg);
        }
        catch (err) {
            this._warnParseIssue(`invalid JSON (${err.message})`, text);
        }
    }
    _extractJsonText(data, isBinary = false) {
        let text = '';
        if (typeof data === 'string') {
            text = data;
        }
        else if (Buffer.isBuffer(data)) {
            text = data.toString('utf8');
        }
        else if (Array.isArray(data)) {
            text = Buffer.concat(data).toString('utf8');
        }
        else if (data instanceof ArrayBuffer) {
            text = Buffer.from(data).toString('utf8');
        }
        else {
            this._warnParseIssue('unsupported frame payload type', typeof data);
            return null;
        }
        const trimmed = text.trim();
        if (!trimmed)
            return null;
        if (!trimmed.startsWith('{') && !trimmed.startsWith('[')) {
            this._warnParseIssue(isBinary ? 'binary non-json frame' : 'text non-json frame', trimmed);
            return null;
        }
        return trimmed;
    }
    _warnParseIssue(reason, payload) {
        const now = Date.now();
        const preview = String(payload || '').replace(/\s+/g, ' ').slice(0, 120);
        if (now - this.lastParseWarnAt >= this.parseWarnWindowMs) {
            if (this.parseWarnSuppressed > 0) {
                console.warn(`[WSS] Suppressed ${this.parseWarnSuppressed} non-JSON frame(s)`);
            }
            this.parseWarnSuppressed = 0;
            this.lastParseWarnAt = now;
            console.warn(`[WSS] Ignored inbound frame: ${reason}${preview ? `; preview="${preview}"` : ''}`);
            return;
        }
        this.parseWarnSuppressed += 1;
    }
    /**
     * Build the connection URL.
     * Default path: /ws/bot/{device_id} (Gateway bot endpoint)
     * If USE_QUERY_AUTH=true, send token via query string.
     */
    _buildWsUrl() {
        let baseUrl = this.config.GATEWAY_WSS_URL;
        const deviceId = this.config.DEVICE_ID;
        // Auto-append device_id to the path if the URL ends with /ws/bot or /ws/bot/
        if (deviceId && /\/ws\/bot\/?$/.test(baseUrl)) {
            baseUrl = baseUrl.replace(/\/+$/, '') + '/' + encodeURIComponent(deviceId);
        }
        if (!this.config.USE_QUERY_AUTH) {
            return baseUrl;
        }
        try {
            const urlObj = new URL(baseUrl);
            urlObj.searchParams.set('device_id', deviceId);
            urlObj.searchParams.set('token', this.config.DEVICE_TOKEN);
            return urlObj.toString();
        }
        catch (err) {
            // Fallback for callers that pass a non-standard URL-like string.
            return `${baseUrl}?device_id=${encodeURIComponent(deviceId)}&token=${encodeURIComponent(this.config.DEVICE_TOKEN)}`;
        }
    }
    _enqueue(envelope) {
        const now = Date.now();
        this.outbox.push({ envelope, ts: now });
        // Trim oldest entries if the buffer grows beyond the limit.
        while (this.outbox.length > this.maxOutbox) {
            this.outbox.shift();
        }
    }
    flushOutbox() {
        if (!this.ws || this.ws.readyState !== WebSocket.OPEN)
            return;
        const now = Date.now();
        const pending = this.outbox;
        this.outbox = [];
        for (const item of pending) {
            if (now - item.ts > this.outboxTtlMs)
                continue;
            try {
                this.ws.send(JSON.stringify(item.envelope));
            }
            catch (err) {
                // Re-queue if send fails.
                this._enqueue(item.envelope);
                break;
            }
        }
    }
}
export default WSSClient;
