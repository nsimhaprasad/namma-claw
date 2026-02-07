import Docker from "dockerode";
import { randomBytes } from "node:crypto";
import { config } from "../config.js";
// Configure Docker socket path
// - macOS with Colima: ~/.colima/default/docker.sock
// - macOS with Docker Desktop: /var/run/docker.sock
// - Linux: /var/run/docker.sock
// - Override with DOCKER_SOCKET env var if set
const socketPath = process.env.DOCKER_SOCKET ||
    (process.platform === 'darwin' && process.env.HOME
        ? `${process.env.HOME}/.colima/default/docker.sock`
        : '/var/run/docker.sock');
export const docker = new Docker({ socketPath });
export async function ensureNetwork() {
    const name = config.docker.network;
    const networks = await docker.listNetworks({ filters: { name: [name] } });
    if (networks.some((n) => n.Name === name)) {
        return;
    }
    await docker.createNetwork({ Name: name, Driver: "bridge" });
}
function gatewayToken() {
    return randomBytes(32).toString("hex");
}
export async function updateOpenClawConfig(params) {
    await initVolume(params);
}
function buildOpenClawConfigJson(params) {
    const basePath = `/openclaw/${params.slug}`;
    const whatsapp = {};
    if (params.ownerE164 && params.ownerE164.trim()) {
        whatsapp.dmPolicy = "allowlist";
        whatsapp.allowFrom = [params.ownerE164.trim()];
    }
    else {
        whatsapp.dmPolicy = "pairing";
    }
    const cfg = {
        gateway: {
            bind: "lan",
            controlUi: params.powerUserEnabled
                ? {
                    enabled: true,
                    basePath,
                    dangerouslyDisableDeviceAuth: true,
                }
                : {
                    enabled: false,
                    dangerouslyDisableDeviceAuth: true,
                },
        },
        channels: {
            whatsapp,
        },
        plugins: {
            entries: {
                whatsapp: {
                    enabled: true,
                },
                ...(params.plugins?.email?.enabled ? { email: { enabled: true } } : {}),
                ...(params.plugins?.twilio?.enabled ? { twilio: { enabled: true } } : {}),
                ...(params.plugins?.slack?.enabled ? { slack: { enabled: true } } : {}),
            },
        },
    };
    const agentsDefaults = {};
    if (params.defaultModel && params.defaultModel.trim()) {
        agentsDefaults.model = { primary: params.defaultModel.trim() };
    }
    if (params.systemPrompt && params.systemPrompt.trim()) {
        agentsDefaults.systemPrompt = params.systemPrompt.trim();
    }
    if (Object.keys(agentsDefaults).length > 0) {
        cfg.agents = { defaults: agentsDefaults };
    }
    return JSON.stringify(cfg, null, 2);
}
async function initVolume(opts) {
    const mountPath = config.docker.dataMountPath;
    const stateDir = `${mountPath}/.openclaw`;
    const workspaceDir = `${mountPath}/workspace`;
    const cfg = buildOpenClawConfigJson(opts);
    const cmd = [
        "sh",
        "-lc",
        [
            `set -euo pipefail`,
            `mkdir -p ${stateDir} ${workspaceDir}`,
            `cat > ${stateDir}/openclaw.json <<'EOF'\n${cfg}\nEOF`,
            `chown -R 1000:1000 ${mountPath}`,
        ].join("\n"),
    ];
    const c = await docker.createContainer({
        Image: "alpine:3.19",
        Cmd: cmd,
        HostConfig: {
            AutoRemove: true,
            Binds: [],
            Mounts: [
                {
                    Type: "volume",
                    Source: opts.volumeName,
                    Target: mountPath,
                },
            ],
        },
    });
    await c.start();
    await c.wait();
}
export async function createOpenClawInstance(params) {
    await ensureNetwork();
    const containerName = `nc-openclaw-${params.instanceId}`;
    const volumeName = `nc-openclaw-data-${params.instanceId}`;
    const token = gatewayToken();
    await docker.createVolume({ Name: volumeName });
    await initVolume({
        volumeName,
        slug: params.slug,
        ownerE164: params.ownerE164,
        defaultModel: params.defaultModel,
        powerUserEnabled: params.powerUserEnabled,
        systemPrompt: params.systemPrompt,
        plugins: params.plugins,
    });
    const envPairs = Object.entries({
        ...params.env,
        OPENCLAW_STATE_DIR: `${config.docker.dataMountPath}/.openclaw`,
        OPENCLAW_WORKSPACE_DIR: `${config.docker.dataMountPath}/workspace`,
        OPENCLAW_GATEWAY_TOKEN: token,
    }).map(([k, v]) => `${k}=${v}`);
    const c = await docker.createContainer({
        name: containerName,
        Image: config.docker.openclawImage,
        Env: envPairs,
        Cmd: ["node", "--max-old-space-size=1536", "dist/index.js", "gateway", "--allow-unconfigured", "--bind", "lan", "--port", "18789"],
        HostConfig: {
            RestartPolicy: { Name: "unless-stopped" },
            Mounts: [
                {
                    Type: "volume",
                    Source: volumeName,
                    Target: config.docker.dataMountPath,
                },
            ],
            Memory: 2 * 1024 * 1024 * 1024,
            NanoCpus: 2_000_000_000,
            PidsLimit: 512,
            PortBindings: {
                "18789/tcp": [{ HostPort: "0" }],
            },
        },
        ExposedPorts: {
            "18789/tcp": {},
        },
        NetworkingConfig: {
            EndpointsConfig: {
                [config.docker.network]: {
                    Aliases: [containerName],
                },
            },
        },
    });
    await c.start();
    const inspectData = await c.inspect();
    const hostPort = inspectData.NetworkSettings.Ports["18789/tcp"]?.[0]?.HostPort;
    if (!hostPort) {
        throw new Error("Failed to get assigned host port for OpenClaw container");
    }
    return {
        containerName,
        volumeName,
        gatewayToken: token,
        wsUrl: `ws://localhost:${hostPort}/openclaw/${params.slug}`,
        hostPort: parseInt(hostPort, 10),
    };
}
export async function recreateOpenClawContainer(params) {
    const containerName = `nc-openclaw-${params.instanceId}`;
    const volumeName = `nc-openclaw-data-${params.instanceId}`;
    // Stop and remove existing container if it exists
    try {
        const existing = docker.getContainer(containerName);
        const info = await existing.inspect();
        if (info.State.Running) {
            await existing.stop();
        }
        await existing.remove();
    }
    catch (err) {
        if (err.statusCode !== 404) {
            throw err;
        }
    }
    // Update config on existing volume
    await initVolume({
        volumeName,
        slug: params.slug,
        ownerE164: params.ownerE164,
        defaultModel: params.defaultModel,
        powerUserEnabled: params.powerUserEnabled,
        systemPrompt: params.systemPrompt,
        plugins: params.plugins,
    });
    const token = gatewayToken();
    const envPairs = Object.entries({
        ...params.env,
        OPENCLAW_STATE_DIR: `${config.docker.dataMountPath}/.openclaw`,
        OPENCLAW_WORKSPACE_DIR: `${config.docker.dataMountPath}/workspace`,
        OPENCLAW_GATEWAY_TOKEN: token,
    }).map(([k, v]) => `${k}=${v}`);
    const c = await docker.createContainer({
        name: containerName,
        Image: config.docker.openclawImage,
        Env: envPairs,
        Cmd: ["node", "--max-old-space-size=1536", "dist/index.js", "gateway", "--allow-unconfigured", "--bind", "lan", "--port", "18789"],
        HostConfig: {
            RestartPolicy: { Name: "unless-stopped" },
            Mounts: [
                {
                    Type: "volume",
                    Source: volumeName,
                    Target: config.docker.dataMountPath,
                },
            ],
            Memory: 2 * 1024 * 1024 * 1024,
            NanoCpus: 2_000_000_000,
            PidsLimit: 512,
            PortBindings: {
                "18789/tcp": [{ HostPort: "0" }],
            },
        },
        ExposedPorts: {
            "18789/tcp": {},
        },
        NetworkingConfig: {
            EndpointsConfig: {
                [config.docker.network]: {
                    Aliases: [containerName],
                },
            },
        },
    });
    await c.start();
    const inspectData = await c.inspect();
    const hostPort = inspectData.NetworkSettings.Ports["18789/tcp"]?.[0]?.HostPort;
    if (!hostPort) {
        throw new Error("Failed to get assigned host port for OpenClaw container");
    }
    return {
        containerName,
        volumeName,
        gatewayToken: token,
        wsUrl: `ws://localhost:${hostPort}/openclaw/${params.slug}`,
        hostPort: parseInt(hostPort, 10),
    };
}
// Stop container (keeps volume and data)
export async function stopOpenClawContainer(containerName) {
    const container = docker.getContainer(containerName);
    const info = await container.inspect();
    if (info.State.Running) {
        await container.stop();
    }
}
// Start stopped container and get new port
export async function startOpenClawContainer(containerName) {
    const container = docker.getContainer(containerName);
    await container.start();
    const inspectData = await container.inspect();
    const hostPort = inspectData.NetworkSettings.Ports["18789/tcp"]?.[0]?.HostPort;
    if (!hostPort) {
        throw new Error("Failed to get assigned host port for OpenClaw container");
    }
    return { hostPort: parseInt(hostPort, 10) };
}
// Delete container and volume
export async function deleteOpenClawInstance(params) {
    // Stop and remove container
    try {
        const container = docker.getContainer(params.containerName);
        const info = await container.inspect();
        if (info.State.Running) {
            await container.stop();
        }
        await container.remove();
    }
    catch (err) {
        if (err.statusCode !== 404)
            throw err;
    }
    // Remove volume
    try {
        const volume = docker.getVolume(params.volumeName);
        await volume.remove();
    }
    catch (err) {
        if (err.statusCode !== 404)
            throw err;
    }
}
