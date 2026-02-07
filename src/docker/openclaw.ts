import Docker from "dockerode";
import { randomBytes } from "node:crypto";
import { config } from "../config.js";

export type InstanceRuntime = {
  containerName: string;
  volumeName: string;
  gatewayToken: string;
  wsUrl: string; // ws://<containerName>:18789/<optionalPath>
  hostPort: number;
};

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

export async function ensureNetwork(): Promise<void> {
  const name = config.docker.network;
  const networks = await docker.listNetworks({ filters: { name: [name] } as any });
  if (networks.some((n) => n.Name === name)) {
    return;
  }
  await docker.createNetwork({ Name: name, Driver: "bridge" });
}

function gatewayToken(): string {
  return randomBytes(32).toString("hex");
}



export async function updateOpenClawConfig(params: {
  volumeName: string;
  slug: string;
  ownerE164?: string | null;
  defaultModel?: string | null;
  powerUserEnabled: boolean;
  systemPrompt?: string | null;
  plugins?: {
    email?: { enabled: boolean; };
    twilio?: { enabled: boolean; };
    slack?: { enabled: boolean; };
  };
}) {
  await initVolume(params);
}

function buildOpenClawConfigJson(params: {
  slug: string;
  ownerE164?: string | null;
  defaultModel?: string | null;
  powerUserEnabled: boolean;
  systemPrompt?: string | null;
  plugins?: {
    email?: { enabled: boolean; };
    twilio?: { enabled: boolean; };
    slack?: { enabled: boolean; };
  };
}): string {
  const basePath = `/openclaw/${params.slug}`;
  const whatsapp: any = {};
  if (params.ownerE164 && params.ownerE164.trim()) {
    whatsapp.dmPolicy = "allowlist";
    whatsapp.allowFrom = [params.ownerE164.trim()];
  } else {
    whatsapp.dmPolicy = "pairing";
  }

  const cfg: any = {
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

  const agentsDefaults: any = {};
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

async function initVolume(opts: {
  volumeName: string;
  slug: string;
  ownerE164?: string | null;
  defaultModel?: string | null;
  powerUserEnabled: boolean;
  systemPrompt?: string | null;
  plugins?: {
    email?: { enabled: boolean; };
    twilio?: { enabled: boolean; };
    slack?: { enabled: boolean; };
  };
}) {
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

export async function createOpenClawInstance(params: {
  instanceId: string;
  slug: string;
  ownerE164?: string | null;
  defaultModel?: string | null;
  powerUserEnabled: boolean;
  systemPrompt?: string | null;
  plugins?: {
    email?: { enabled: boolean };
    twilio?: { enabled: boolean };
    slack?: { enabled: boolean };
  };
  env: Record<string, string>;
}): Promise<InstanceRuntime> {
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

export async function recreateOpenClawContainer(params: {
  instanceId: string;
  slug: string;
  ownerE164?: string | null;
  defaultModel?: string | null;
  powerUserEnabled: boolean;
  systemPrompt?: string | null;
  plugins?: {
    email?: { enabled: boolean };
    twilio?: { enabled: boolean };
    slack?: { enabled: boolean };
  };
  env: Record<string, string>;
}): Promise<InstanceRuntime> {
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
  } catch (err: any) {
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

// Clear WhatsApp session data from volume (for reset)
// Deletes everything in .openclaw EXCEPT openclaw.json config
export async function clearWhatsAppSession(volumeName: string): Promise<void> {
  const mountPath = config.docker.dataMountPath;
  const stateDir = `${mountPath}/.openclaw`;

  // Delete everything except openclaw.json config file
  // This ensures all session/auth data is cleared
  const cmd = [
    "sh",
    "-c",
    `cd ${stateDir} 2>/dev/null && find . -mindepth 1 ! -name 'openclaw.json' -exec rm -rf {} + 2>/dev/null; ls -la ${stateDir}; echo "Cleared all session data"`,
  ];

  const c = await docker.createContainer({
    Image: "alpine:3.19",
    Cmd: cmd,
    HostConfig: {
      AutoRemove: true,
      Mounts: [
        {
          Type: "volume",
          Source: volumeName,
          Target: mountPath,
        },
      ],
    },
  });
  await c.start();
  const result = await c.wait();
  console.log(`[clearWhatsAppSession] Container exited with code ${result.StatusCode}`);
}

// Stop container (keeps volume and data)
export async function stopOpenClawContainer(containerName: string): Promise<void> {
  const container = docker.getContainer(containerName);
  const info = await container.inspect();
  if (info.State.Running) {
    await container.stop();
  }
}

// Start stopped container and get new port
export async function startOpenClawContainer(containerName: string): Promise<{ hostPort: number }> {
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
export async function deleteOpenClawInstance(params: {
  containerName: string;
  volumeName: string;
}): Promise<void> {
  // Stop and remove container
  try {
    const container = docker.getContainer(params.containerName);
    const info = await container.inspect();
    if (info.State.Running) {
      await container.stop();
    }
    await container.remove();
  } catch (err: any) {
    if (err.statusCode !== 404) throw err;
  }
  // Remove volume
  try {
    const volume = docker.getVolume(params.volumeName);
    await volume.remove();
  } catch (err: any) {
    if (err.statusCode !== 404) throw err;
  }
}
