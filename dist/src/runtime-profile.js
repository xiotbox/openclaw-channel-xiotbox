/**
 * OpenClaw capability declaration — explicit device facts (XIOT-BUG-0050a).
 *
 * This module is the single source of truth for the capability declaration the
 * channel publishes. The wire placement is the Gateway 0048a contract input:
 * `bot_ws._handle_runtimes_list` reads `runtime.capabilities` from each
 * RUNTIMES.LIST entry and `platform_service.register_bot_session` reads
 * `capabilities` from each SESSION.REGISTER payload, then feeds the object
 * through `runtime_profile.normalize_declaration`. A declaration published
 * under any other key is silently dropped by the gateway, so the key name is
 * pinned by test/runtime-profile.test.mjs and
 * test/runtime-visibility.test.mjs.
 *
 * Declaration shape rules (XIOT-PLAN-0008 §3.1/§3.2 + gateway 0048a
 * runtime_profile.py):
 * - `capabilities_version` must be the strict integer 1.
 * - Values are tri-state facts: strict JSON true/false (the literal string
 *   "unknown" is never produced by this builder — an absent key is how the
 *   device says "no fact").
 * - The device NEVER self-reports the gateway-normalized `contract_level`:
 *   the gateway derives "v1"/"legacy" itself from the declared Core facts.
 *   0050a does not implement the canonical COMMAND_ACK lifecycle (that is
 *   0050b), so this declaration states `command_ack: false` — which truthfully
 *   pins the derived contract level at "legacy". Declaring ack=true would let
 *   the gateway derive v1 for a runtime that cannot ack.
 * - `models` / `workspaces` are resource data and stay OUT of the declaration;
 *   they ride on the RUNTIMES.LIST runtime entry next to `capabilities`.
 * - Adapter-namespaced extensions (§3.4.1) use dotted keys. CROSS-REPO SEAM
 *   (recorded, not hidden): `openclaw.binding_registry` is REGISTERED on the
 *   gateway (runtime_profile.py REGISTERED_EXTENSIONS, review round 3 of the
 *   0048a PR #16), so the gateway now preserves it verbatim in the normalized
 *   profile (profile.extensions + provenance.extensions_preserved).
 *   Preservation is not consumption: no control-plane consumer acts on the
 *   value yet — 0050a only guarantees the declared fact survives the gateway
 *   round-trip. Pinned by test/runtime-profile.test.mjs.
 */
/**
 * Stable runtime kind. The gateway default is deliberately neutral
 * (XIOT-BUG-0001 / XIOT-BUG-0007), so this must be declared explicitly.
 */
export const OPENCLAW_RUNTIME_KIND = 'openclaw';
/** Version of the capability declaration schema (0048a CAPABILITIES_VERSION). */
export const OPENCLAW_CAPABILITIES_VERSION = 1;
/**
 * Binding registry lifecycle. `process_local` is the truthful value today:
 * the conversation binding registry (src/channel.ts) and the session model
 * override map (src/session-model.ts) are in-memory only — they reset on a
 * plugin restart and re-register on the next chat message. `persistent` would
 * require a durable store that does not exist yet; declaring it would be a
 * lie. The lifecycle is made explicit so upstream knows that model selection
 * and session.* command routing lose their in-memory bindings across a
 * restart until re-registration.
 */
export const OPENCLAW_BINDING_REGISTRY_LIFECYCLE = 'process_local';
/**
 * The OpenClaw host exposes no static model catalog seam to the channel, so
 * the runtime publishes no model list. This is independent from model
 * selection: see OPENCLAW_BINDING_REGISTRY_CAN_SELECT below.
 */
export const OPENCLAW_MODEL_CATALOG_AVAILABLE = false;
/**
 * Independent of the model catalog: the binding registry supports per-session
 * model selection (`session.model.select` → setSessionModelOverride), so
 * `model_selection` stays true even though `model_catalog` is false.
 */
export const OPENCLAW_BINDING_REGISTRY_CAN_SELECT = true;
/** E2E command envelope (XIOT-PLAN-0008 §3.2 / §3.4.1: OGE2E1 version 1). */
export const OPENCLAW_E2E_ENVELOPE = 'OGE2E1';
/** E2E command envelope algorithm, as implemented by src/e2e.ts. */
export const OPENCLAW_E2E_ALG = 'x25519+AES-256-GCM';
/**
 * Build the explicit OpenClaw capability declaration. Pure: no filesystem or
 * network access, so it is fully unit-testable and safe to inline into every
 * RUNTIMES.LIST entry and SESSION.REGISTER payload.
 *
 * Field notes (all pinned by tests):
 * - `conversation_create: true` is the NEUTRAL create path: the platform
 *   (gateway) creates the conversation and the channel registers the binding
 *   (SESSION.REGISTER). The absence of a native `session.create` command is
 *   NOT a reason to declare false — that would misreport branch B of the
 *   conversation.ensure contract as unsupported.
 * - `conversation_delete` is intentionally NOT asserted by the device: there
 *   is no device-side delete seam in this channel, and the 0048a adapter
 *   static contract for openclaw.v1 owns that fact. An absent optional key
 *   normalizes to "unknown" and is then filled by the static contract — the
 *   device never guesses.
 * - `e2e.control_plane_identity` is intentionally NOT declared: the control
 *   plane identity line is 0046c, so the gateway normalizes it to "unknown".
 * - `model_selection` is detected independently from `model_catalog`: a
 *   caller that knows the binding registry lost its select seam can pass
 *   `modelSelection: false`, while `model_catalog` stays untouched.
 */
export function buildOpenclawCapabilityDeclaration(options = {}) {
    const bindingRegistry = options.bindingRegistry ?? OPENCLAW_BINDING_REGISTRY_LIFECYCLE;
    const modelSelection = options.modelSelection ?? OPENCLAW_BINDING_REGISTRY_CAN_SELECT;
    return {
        capabilities_version: OPENCLAW_CAPABILITIES_VERSION,
        // Core: chat works (E2E-gated), user/assistant messages are projected into
        // conversation lifecycle events (src/conversation-projection.ts), run
        // started/completed/failed are emitted (src/channel.ts), the canonical ACK
        // lifecycle does NOT exist yet (command_ack=false, 0050b), this very
        // advertisement proves capability_advertisement, and the e2e block below
        // is the e2e_policy_declaration fact.
        message_send: true,
        message_user_projection: true,
        run_lifecycle: true,
        command_ack: false,
        capability_advertisement: true,
        e2e_policy_declaration: true,
        // Optional: rename/fork hit unsupported_command_type (channel.ts
        // resolveSessionCommandAction); archive has a real ACKed path; interrupt
        // fails honestly with interrupt_unavailable; the queue family has no
        // seam; ask_user is projected (resolveOption only — no custom answers,
        // XIOT-BUG-0008); approvals ride approval-lifecycle; per-session
        // permission arrives as chat metadata (full | readonly); tool events,
        // reasoning blocks, subagents and attachments are all projected.
        conversation_create: true,
        conversation_rename: false,
        conversation_archive: true,
        conversation_fork: false,
        workspace_context: true,
        workspace_create: false,
        model_selection: modelSelection,
        model_catalog: OPENCLAW_MODEL_CATALOG_AVAILABLE,
        interrupt: false,
        queue: false,
        queue_edit: false,
        queue_remove: false,
        queue_promote: false,
        ask_user: true,
        ask_user_custom: false,
        approvals: true,
        permissions_set: true,
        tool_events: true,
        reasoning: true,
        subagents: true,
        attachments: true,
        goal: false,
        // E2E policy (0048a normalize_e2e_declaration shape): required_for_commands
        // must be a strict JSON bool; envelope/alg are non-empty strings. Chat
        // commands without a valid OGE2E1 envelope fail with e2e_required — that
        // enforcement is the OGE2E1 security boundary and is NOT relaxed here.
        e2e: {
            required_for_commands: true,
            envelope: OPENCLAW_E2E_ENVELOPE,
            alg: OPENCLAW_E2E_ALG,
        },
        // Adapter-namespaced extension (XIOT-PLAN-0008 §3.4.1). See the module
        // docblock for the cross-repo seam: declared here, not yet consumed by
        // the 0048a gateway provider.
        'openclaw.binding_registry': bindingRegistry,
    };
}
/**
 * Resource facts that ride NEXT TO the declaration on the RUNTIMES.LIST
 * runtime entry. The local path never leaves the Runtime. When OpenClaw's
 * native persistent workspace exists, XiotBox publishes only its stable id,
 * display name and access/execution facts.
 */
export function buildOpenclawResourceFacts(workspaceAvailable = false) {
    return {
        workspaces: workspaceAvailable
            ? [{
                    workspace_id: 'workspace',
                    name: 'OpenClaw Workspace',
                    readable: true,
                    writable: true,
                    executable: true,
                    execution_profiles: ['safe', 'full.workspace'],
                }]
            : [],
        models: [],
    };
}
