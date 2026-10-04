import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
export const OPENCLAW_WORKSPACE_ID = 'workspace';
export const OPENCLAW_WORKSPACE_NAME = 'OpenClaw Workspace';
function text(value) {
    return typeof value === 'string' ? value.trim() : '';
}
/**
 * Resolve the workspace already owned by OpenClaw. In Docker deployments the
 * upstream compose pins OPENCLAW_WORKSPACE_DIR inside the container to
 * /home/node/.openclaw/workspace while bind-mounting a persistent host path.
 * XiotBox never invents a second workspace location.
 */
export function resolveOpenclawWorkspacePath(cfg) {
    const configured = text(process.env.OPENCLAW_WORKSPACE_DIR) ||
        text(cfg?.agents?.entries?.main?.workspace) ||
        text(cfg?.agents?.defaults?.workspace);
    if (configured)
        return configured;
    const home = text(process.env.HOME) || homedir();
    return home ? join(home, '.openclaw', 'workspace') : '';
}
export function openclawWorkspaceAvailable(cfg) {
    const workspace = resolveOpenclawWorkspacePath(cfg);
    return Boolean(workspace && existsSync(workspace));
}
export function buildOpenclawWorkspaceRegistry(runtimeId, cfg) {
    const workspacePath = resolveOpenclawWorkspacePath(cfg);
    return {
        async resolve(requestedRuntimeId, workspaceId) {
            if (requestedRuntimeId !== runtimeId || workspaceId !== OPENCLAW_WORKSPACE_ID)
                return undefined;
            if (!workspacePath || !existsSync(workspacePath))
                return undefined;
            return {
                localPath: workspacePath,
                readable: true,
                writable: true,
                executable: true,
            };
        },
    };
}
