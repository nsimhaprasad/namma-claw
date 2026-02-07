import express from "express";
import cookieParser from "cookie-parser";
import http from "node:http";
import httpProxy from "http-proxy";
import { z } from "zod";
import { v4 as uuidv4 } from "uuid";

import { config } from "./config.js";
import { query } from "./db/db.js";
import {
  clearSessionCookie,
  hashPassword,
  requireAuth,
  setSessionCookie,
  signSession,
  verifyPassword,
  type AuthedRequest,
} from "./auth.js";
import { decryptSecret, encryptSecret } from "./crypto.js";
import { page, escapeHtml } from "./views.js";
import { OpenClawWsClient } from "./openclaw/ws-client.js";
import {
  docker,
  ensureNetwork,
  createOpenClawInstance,
  recreateOpenClawContainer,
  updateOpenClawConfig,
} from "./docker/openclaw.js";

const app = express();
app.use(express.urlencoded({ extended: true, limit: "256kb" }));
app.use(express.json({ limit: "256kb" }));
app.use(cookieParser());

const proxy = httpProxy.createProxyServer({ ws: true });

type UserRow = { id: string; email: string; password_hash: string };
type InstanceRow = {
  id: string;
  user_id: string;
  slug: string;
  status: string;
  container_name: string;
  state_volume: string;
  owner_e164: string | null;
  default_model: string | null;
  system_prompt: string | null;
  plugins_config: string | null; // JSON string
  power_user_enabled: boolean;
};

const SlugSchema = z
  .string()
  .trim()
  .min(2)
  .max(32)
  .regex(/^[a-z][a-z0-9-]+$/, "slug must be dns-safe (a-z, 0-9, '-')");

const SecretKeyAllowlist = new Set<string>([
  "OPENAI_API_KEY",
  "ANTHROPIC_API_KEY",
  "ANTHROPIC_OAUTH_TOKEN",
  "GEMINI_API_KEY",
  "ZAI_API_KEY",
  "OPENROUTER_API_KEY",
  "AI_GATEWAY_API_KEY",
  "AI_GATEWAY_API_KEY",
  "MINIMAX_API_KEY",
  "SYNTHETIC_API_KEY",
  "DEEPGRAM_API_KEY",
  // Plugin Specific
  "SMTP_HOST",
  "SMTP_PORT",
  "SMTP_USER",
  "SMTP_PASSWORD",
  "TWILIO_ACCOUNT_SID",
  "TWILIO_AUTH_TOKEN",
  "TWILIO_FROM_NUMBER",
  "SLACK_BOT_TOKEN",
  "SLACK_SIGNING_SECRET",
]);

const SupportedModels = [
  { id: "google/gemini-3-flash-preview", label: "Google Gemini 1.5 Flash" },
  { id: "google/gemini-1.5-pro-latest", label: "Google Gemini 1.5 Pro" },
  { id: "anthropic/claude-opus-4-6", label: "Anthropic Claude 3 Opus" },
  { id: "anthropic/claude-sonnet-4-5", label: "Anthropic Claude 3.5 Sonnet" },
  { id: "openai/gpt-5.2", label: "OpenAI GPT-4o" },
  { id: "openai/gpt-5-mini", label: "OpenAI GPT-4o Mini" },
];

async function getInstanceBySlug(slug: string): Promise<InstanceRow | null> {
  const rows = await query<InstanceRow>("select * from instances where slug=$1 limit 1", [slug]);
  return rows[0] ?? null;
}

async function userHasInstanceAccess(userId: string, instanceId: string): Promise<boolean> {
  const rows = await query<{ ok: boolean }>(
    "select true as ok from instance_members where instance_id=$1 and user_id=$2 limit 1",
    [instanceId, userId],
  );
  return Boolean(rows[0]?.ok);
}

async function getInstanceSecrets(instanceId: string): Promise<Record<string, string>> {
  const rows = await query<{ key: string; ciphertext: string }>(
    "select key, ciphertext from instance_secrets where instance_id=$1",
    [instanceId],
  );
  const out: Record<string, string> = {};
  for (const r of rows) {
    out[r.key] = decryptSecret(r.ciphertext);
  }
  return out;
}

async function upsertInstanceSecret(instanceId: string, key: string, value: string) {
  const ciphertext = encryptSecret(value);
  await query(
    `
    insert into instance_secrets (id, instance_id, key, ciphertext)
    values ($1,$2,$3,$4)
    on conflict (instance_id, key)
    do update set ciphertext=excluded.ciphertext, updated_at=now()
  `,
    [uuidv4(), instanceId, key, ciphertext],
  );
}

function requireSslInProd() {
}

app.get("/", (req, res) => {
  res.redirect("/instances");
});

app.get("/signup", (_req, res) => {
  res.send(
    page(
      "Sign up",
      `
      <article class="grid">
        <div>
          <hgroup>
            <h1>Sign up</h1>
            <h2>Create your OpenClaw account</h2>
          </hgroup>
          <form method="post" action="/signup">
            <label>Email <input name="email" type="email" placeholder="you@example.com" required /></label>
            <label>Password <input name="password" type="password" required /></label>
            <button type="submit">Create account</button>
          </form>
          <p><small>Already have an account? <a href="/login">Login</a></small></p>
        </div>
      </article>
    `,
    ),
  );
});

app.post("/signup", async (req, res) => {
  const email = String(req.body?.email ?? "").trim().toLowerCase();
  const password = String(req.body?.password ?? "");
  if (!email || password.length < 8) {
    res.status(400).send("invalid email/password");
    return;
  }
  const existing = await query<UserRow>("select * from users where email=$1 limit 1", [email]);
  if (existing[0]) {
    res.status(400).send("email already registered");
    return;
  }
  const userId = uuidv4();
  const passwordHash = await hashPassword(password);
  await query("insert into users (id,email,password_hash) values ($1,$2,$3)", [
    userId,
    email,
    passwordHash,
  ]);
  const token = signSession({ userId, email });
  setSessionCookie(res, token);
  res.redirect("/instances");
});

app.get("/login", (_req, res) => {
  res.send(
    page(
      "Login",
      `
      <article class="grid">
        <div>
          <hgroup>
            <h1>Login</h1>
            <h2>Welcome back to OpenClaw</h2>
          </hgroup>
          <form method="post" action="/login">
            <label>Email <input name="email" type="email" placeholder="you@example.com" required /></label>
            <label>Password <input name="password" type="password" required /></label>
            <button type="submit">Login</button>
          </form>
          <p><small>Don't have an account? <a href="/signup">Sign up</a></small></p>
        </div>
      </article>
    `,
    ),
  );
});

app.post("/login", async (req, res) => {
  const email = String(req.body?.email ?? "").trim().toLowerCase();
  const password = String(req.body?.password ?? "");
  const rows = await query<UserRow>("select * from users where email=$1 limit 1", [email]);
  const user = rows[0];
  if (!user) {
    res.status(400).send("invalid credentials");
    return;
  }
  const ok = await verifyPassword(password, user.password_hash);
  if (!ok) {
    res.status(400).send("invalid credentials");
    return;
  }
  const token = signSession({ userId: user.id, email: user.email });
  setSessionCookie(res, token);
  res.redirect("/instances");
});

app.post("/logout", (req, res) => {
  clearSessionCookie(res);
  res.redirect("/login");
});

app.get("/instances", requireAuth, async (req, res) => {
  const session = (req as AuthedRequest).session;
  const rows = await query<InstanceRow>(
    `
    select i.* from instances i
    join instance_members m on m.instance_id=i.id
    where m.user_id=$1
    order by i.created_at desc
  `,
    [session.userId],
  );

  const list = rows
    .map(
      (i) => `
      <article>
        <header class="card-header-actions">
          <strong>${escapeHtml(i.slug)}</strong>
          <span class="muted-text">${escapeHtml(i.status)}</span>
        </header>
        <div class="grid">
          <div>
            <a role="button" href="/i/${encodeURIComponent(i.slug)}">Open Dashboard</a>
            ${i.power_user_enabled
          ? `<a role="button" class="secondary outline" href="/i/${encodeURIComponent(i.slug)}/openclaw">OpenClaw GUI</a>`
          : ``
        }
          </div>
        </div>
      </article>
    `,
    )
    .join("\n");

  res.send(
    page(
      "Instances",
      `
      <hgroup>
        <h1>Your Instances</h1>
        <h2>Manage your OpenClaw containers</h2>
      </hgroup>
      
      <article>
        <header><strong>Create New Instance</strong></header>
        <form method="post" action="/instances" style="margin-bottom: 0;">
          <fieldset role="group">
            <input name="slug" placeholder="Instance Name (e.g. jarvis)" required />
            <button type="submit">Create</button>
          </fieldset>
          <small class="muted-text">Provisions a dedicated docker container.</small>
        </form>
      </article>

      ${list || `<article><p class="muted-text">No instances yet.</p></article>`}
    `,
    ),
  );
});

app.post("/instances", requireAuth, async (req, res) => {
  const session = (req as AuthedRequest).session;
  const slug = SlugSchema.safeParse(req.body?.slug);
  if (!slug.success) {
    res.status(400).send(slug.error.message);
    return;
  }
  const exists = await getInstanceBySlug(slug.data);
  if (exists) {
    res.status(400).send("slug already exists");
    return;
  }

  const instanceId = uuidv4();
  const containerName = `nc-openclaw-${instanceId}`;
  const volumeName = `nc-openclaw-data-${instanceId}`;

  await query(
    `
    insert into instances (id,user_id,slug,status,container_name,state_volume)
    values ($1,$2,$3,$4,$5,$6)
  `,
    [instanceId, session.userId, slug.data, "creating", containerName, volumeName],
  );
  await query(
    `insert into instance_members (instance_id, user_id, role) values ($1,$2,$3)`,
    [instanceId, session.userId, "owner"],
  );

  const runtime = await createOpenClawInstance({
    instanceId,
    slug: slug.data,
    powerUserEnabled: false,
    env: {},
  });
  await upsertInstanceSecret(instanceId, "OPENCLAW_GATEWAY_TOKEN", runtime.gatewayToken);
  await query("update instances set status=$1 where id=$2", ["running", instanceId]);

  res.redirect(`/i/${encodeURIComponent(slug.data)}`);
});

app.get("/i/:slug/status", requireAuth, async (req, res) => {
  const session = (req as AuthedRequest).session;
  const inst = await getInstanceBySlug(String(req.params.slug || ""));
  if (!inst || !(await userHasInstanceAccess(session.userId, inst.id))) {
    return res.status(404).json({ error: "not found" });
  }

  try {
    const container = docker.getContainer(inst.container_name);
    const stats = await container.inspect();
    const isRunning = stats.State.Running;

    res.json({
      status: isRunning ? "running" : "stopped",
      startedAt: stats.State.StartedAt,
      restartTime: stats.State.Restarting ? "restarting" : null,
      memory: "2GB Limit", // Static for now, could be dynamic
    });
  } catch (err) {
    res.json({ status: "error", error: String(err) });
  }
});

app.get("/i/:slug", requireAuth, async (req, res) => {
  const session = (req as AuthedRequest).session;
  const slug = String(req.params.slug || "");
  const inst = await getInstanceBySlug(slug);
  if (!inst) {
    res.status(404).send("not found");
    return;
  }
  if (!(await userHasInstanceAccess(session.userId, inst.id))) {
    res.status(403).send("forbidden");
    return;
  }
  const secrets = await getInstanceSecrets(inst.id);
  const savedKeys = Object.keys(secrets).filter((k) => SecretKeyAllowlist.has(k));

  res.send(
    page(
      `Instance ${inst.slug}`,
      `
      <header class="container" style="padding-bottom: 0; border: none; margin-bottom: 1rem;">
        <nav aria-label="breadcrumb">
          <ul>
            <li><a href="/instances">Instances</a></li>
            <li>${escapeHtml(inst.slug)}</li>
          </ul>
        </nav>
        <hgroup>
            <h1>${escapeHtml(inst.slug)}</h1>
            <h2><span id="status-dot" class="status-dot"></span> <span id="status-text">Checking status...</span></h2>
        </hgroup>
      </header>
      
      <div class="grid">
        <!-- Main Configuration Column -->
        <div>
           <!-- WhatsApp Card -->
          <article>
            <header><strong>WhatsApp Integration</strong></header>
            <form method="post" action="/i/${encodeURIComponent(inst.slug)}/owner">
              <label>
                Owner Phone Number (E.164 format, e.g. +15551234567)
                <small class="muted-text">Restricts access to this number only.</small>
                <fieldset role="group">
                    <input name="ownerE164" placeholder="+15551234567" value="${escapeHtml(inst.owner_e164 || "")}" />
                    <button type="submit" class="secondary">Save</button>
                </fieldset>
              </label>
            </form>

            <div class="grid">
              <form method="post" action="/i/${encodeURIComponent(inst.slug)}/whatsapp/qr/start">
                <button type="submit">Show QR Code</button>
              </form>
              <form method="post" action="/i/${encodeURIComponent(inst.slug)}/whatsapp/qr/wait">
                <button type="submit" class="outline">Check Connection</button>
              </form>
            </div>
          </article>

          <!-- Model Config -->
          <article>
            <header><strong>AI Model</strong></header>
            <form method="post" action="/i/${encodeURIComponent(inst.slug)}/model">
              <label>
                Default Model
                <select name="defaultModel">
                    <option value="" ${!inst.default_model ? "selected" : ""}>Select a model...</option>
                    ${SupportedModels.map(
        m => `<option value="${m.id}" ${inst.default_model === m.id ? "selected" : ""}>${m.label}</option>`
      ).join("")}
                </select>
              </label>
              <button type="submit">Update Model</button>
            </form>
          </article>
      
        </div>

        <!-- Secrets & System Column -->
        <div>
          <!-- Secrets -->
           <article>
            <header><strong>API Keys</strong></header>
            ${savedKeys.length > 0
        ? `<p><small class="muted-text">Configured: ${savedKeys.map(k => `<span data-tooltip="Configured">✅ ${k.split('_')[0]}</span>`).join(", ")}</small></p>`
        : `<p><small class="muted-text">No keys configured.</small></p>`}
            
            <form method="post" action="/i/${encodeURIComponent(inst.slug)}/secrets">
              <label>
                Provider Key
                <select name="key" required>
                  <option value="" disabled selected>Select Provider...</option>
                  ${Array.from(SecretKeyAllowlist).sort().map(k => `<option value="${escapeHtml(k)}">${escapeHtml(k)}</option>`).join("")}
                </select>
              </label>
              <label>
                Secret Value
                <input name="value" type="password" placeholder="sk-..." required />
              </label>
              <button type="submit">Save Secret</button>
              <small class="muted-text">Saving will restart the container.</small>
            </form>
          </article>

          </article>

          <!-- Advanced Configuration -->
          <article>
            <header><strong>Advanced Configuration</strong></header>
            <form method="post" action="/i/${encodeURIComponent(inst.slug)}/config">
              <label>
                System Prompt
                <small class="muted-text">Override the default behavior and persona.</small>
                <textarea name="systemPrompt" rows="4" placeholder="You do NOT need to set this if using default model behavior.">${escapeHtml(inst.system_prompt || "")}</textarea>
              </label>
              
              <hr />
              
              <strong>Plugins</strong>
              <small class="muted-text display-block" style="margin-bottom: 0.5rem;">Enable additional integrations. Configure their keys in the 'API Keys' section.</small>
              
              <label>
                <input type="checkbox" name="plugin_email" ${inst.plugins_config && JSON.parse(inst.plugins_config).email?.enabled ? "checked" : ""} />
                Enable Email (requires SMTP keys)
              </label>
              <label>
                <input type="checkbox" name="plugin_twilio" ${inst.plugins_config && JSON.parse(inst.plugins_config).twilio?.enabled ? "checked" : ""} />
                Enable Twilio (SMS/Voice)
              </label>
              <label>
                <input type="checkbox" name="plugin_slack" ${inst.plugins_config && JSON.parse(inst.plugins_config).slack?.enabled ? "checked" : ""} />
                Enable Slack
              </label>

              <button type="submit" class="secondary outline">Update Configuration</button>
            </form>
          </article>

          <!-- System Ops -->
          <article>
            <header><strong>System Operations</strong></header>
            <form method="post" action="/i/${encodeURIComponent(inst.slug)}/restart">
                <button type="submit" class="contrast outline">Restart Container</button>
            </form>
            
            <hr />
            
             <form method="post" action="/i/${encodeURIComponent(inst.slug)}/power">
              <label>
                <input type="checkbox" name="enabled" value="true" ${inst.power_user_enabled ? "checked" : ""} />
                Enable OpenClaw Developer Dashboard
              </label>
              <button type="submit" class="secondary">Save Preference</button>
            </form>
             ${inst.power_user_enabled
        ? `<a role="button" href="/i/${encodeURIComponent(inst.slug)}/openclaw" class="contrast">Launch Dashboard</a>`
        : ``
      }
          </article>
        </div>
      </div>
    `,
      `
    // Client-side status polling
    async function updateStatus() {
        try {
            const res = await fetch('/i/${encodeURIComponent(inst.slug)}/status');
            const data = await res.json();
            const dot = document.getElementById('status-dot');
            const text = document.getElementById('status-text');
            
            dot.className = 'status-dot ' + (data.status === 'running' ? 'running' : 'stopped');
            text.textContent = data.status === 'running' 
                ? 'Running (Up since ' + new Date(data.startedAt).toLocaleTimeString() + ')' 
                : 'Stopped';
        } catch (e) {
            console.error('Status poll failed', e);
        }
    }
    
    // Poll every 5 seconds
    setInterval(updateStatus, 5000);
    updateStatus(); // Initial call
    `
    ),
  );
});


app.post("/i/:slug/restart", requireAuth, async (req, res) => {
  const session = (req as AuthedRequest).session;
  const inst = await getInstanceBySlug(String(req.params.slug || ""));
  if (!inst) return res.status(404).send("not found");
  if (!(await userHasInstanceAccess(session.userId, inst.id))) return res.status(403).send("forbidden");
  await rebootInstance(inst);
  res.redirect(`/i/${encodeURIComponent(inst.slug)}`);
});

app.post("/i/:slug/secrets", requireAuth, async (req, res) => {
  const session = (req as AuthedRequest).session;
  const inst = await getInstanceBySlug(String(req.params.slug || ""));
  if (!inst) return res.status(404).send("not found");
  if (!(await userHasInstanceAccess(session.userId, inst.id))) return res.status(403).send("forbidden");
  const key = String(req.body?.key ?? "").trim();
  const value = String(req.body?.value ?? "");
  if (!SecretKeyAllowlist.has(key)) return res.status(400).send("unsupported key");
  if (!value.trim()) return res.status(400).send("empty value");
  await upsertInstanceSecret(inst.id, key, value.trim());
  // Restart container to pick up new environment variables
  await rebootInstance(inst);
  res.redirect(`/i/${encodeURIComponent(inst.slug)}`);
});

app.post("/i/:slug/model", requireAuth, async (req, res) => {
  const session = (req as AuthedRequest).session;
  const inst = await getInstanceBySlug(String(req.params.slug || ""));
  if (!inst) return res.status(404).send("not found");
  if (!(await userHasInstanceAccess(session.userId, inst.id))) return res.status(403).send("forbidden");
  const model = String(req.body?.defaultModel ?? "").trim();
  await query("update instances set default_model=$1, updated_at=now() where id=$2", [model || null, inst.id]);
  await updateOpenClawConfig({
    volumeName: inst.state_volume,
    slug: inst.slug,
    ownerE164: inst.owner_e164,
    defaultModel: model || null,
    powerUserEnabled: inst.power_user_enabled,
  });
  await rebootInstance(inst);
  res.redirect(`/i/${encodeURIComponent(inst.slug)}`);
});

app.post("/i/:slug/owner", requireAuth, async (req, res) => {
  const session = (req as AuthedRequest).session;
  const inst = await getInstanceBySlug(String(req.params.slug || ""));
  if (!inst) return res.status(404).send("not found");
  if (!(await userHasInstanceAccess(session.userId, inst.id))) return res.status(403).send("forbidden");
  const ownerE164 = String(req.body?.ownerE164 ?? "").trim();
  await query("update instances set owner_e164=$1, updated_at=now() where id=$2", [ownerE164 || null, inst.id]);
  await updateOpenClawConfig({
    volumeName: inst.state_volume,
    slug: inst.slug,
    ownerE164: ownerE164 || null,
    defaultModel: inst.default_model,
    powerUserEnabled: inst.power_user_enabled,
  });
  await rebootInstance(inst);
  res.redirect(`/i/${encodeURIComponent(inst.slug)}`);
});

async function rebootInstance(inst: InstanceRow) {
  const secrets = await getInstanceSecrets(inst.id);
  // Recreate container to apply new env vars
  const runtime = await recreateOpenClawContainer({
    instanceId: inst.id,
    slug: inst.slug,
    ownerE164: inst.owner_e164,
    defaultModel: inst.default_model,
    powerUserEnabled: inst.power_user_enabled,
    systemPrompt: inst.system_prompt,
    plugins: inst.plugins_config ? JSON.parse(inst.plugins_config) : undefined,
    env: secrets,
  });
  // Update gateway token since recreation generates a new one
  await upsertInstanceSecret(inst.id, "OPENCLAW_GATEWAY_TOKEN", runtime.gatewayToken);
}

async function withOpenClawClient(inst: InstanceRow, fn: (c: OpenClawWsClient) => Promise<any>) {
  const secrets = await getInstanceSecrets(inst.id);
  const token = secrets.OPENCLAW_GATEWAY_TOKEN;
  if (!token) {
    throw new Error("missing gateway token secret");
  }

  // Get the container's exposed port
  const { docker } = await import("./docker/openclaw.js");
  const container = docker.getContainer(inst.container_name);

  let inspectData;
  try {
    inspectData = await container.inspect();
  } catch (err: any) {
    if (err.statusCode === 404) {
      throw new Error(`Container ${inst.container_name} not found. Try restarting the instance.`);
    }
    throw err;
  }

  if (!inspectData.State.Running) {
    throw new Error(`Container ${inst.container_name} is not running. Try restarting the instance.`);
  }

  const hostPort = inspectData.NetworkSettings.Ports["18789/tcp"]?.[0]?.HostPort;
  if (!hostPort) {
    throw new Error(`Container ${inst.container_name} has no exposed port. Try restarting the instance.`);
  }

  // OpenClaw gateway WebSocket is at root path, not at basePath
  const wsUrl = `ws://localhost:${hostPort}`;
  console.log(`[withOpenClawClient] Connecting to ${wsUrl} for instance ${inst.slug}`);

  const client = new OpenClawWsClient(wsUrl, token);
  try {
    await client.connect();
    console.log(`[withOpenClawClient] Connected successfully to ${inst.slug}`);
    return await fn(client);
  } catch (err) {
    console.error(`[withOpenClawClient] Failed to connect to ${wsUrl}:`, err);
    throw err;
  } finally {
    client.close();
  }
}

app.post("/i/:slug/config", requireAuth, async (req, res) => {
  const session = (req as AuthedRequest).session;
  const inst = await getInstanceBySlug(String(req.params.slug || ""));
  if (!inst) return res.status(404).send("not found");
  if (!(await userHasInstanceAccess(session.userId, inst.id))) return res.status(403).send("forbidden");

  const systemPrompt = String(req.body?.systemPrompt || "").trim();

  const plugins = {
    email: { enabled: req.body?.plugin_email === "on" },
    twilio: { enabled: req.body?.plugin_twilio === "on" },
    slack: { enabled: req.body?.plugin_slack === "on" },
  };

  await query(
    "update instances set system_prompt=$1, plugins_config=$2, updated_at=now() where id=$3",
    [systemPrompt || null, JSON.stringify(plugins), inst.id]
  );

  // Re-fetch to get latest state for config rebuild
  const updatedInst = await getInstanceBySlug(inst.slug);
  if (updatedInst) {
    await updateOpenClawConfig({
      volumeName: updatedInst.state_volume,
      slug: updatedInst.slug,
      ownerE164: updatedInst.owner_e164,
      defaultModel: updatedInst.default_model,
      powerUserEnabled: updatedInst.power_user_enabled,
      systemPrompt: updatedInst.system_prompt,
      plugins: updatedInst.plugins_config ? JSON.parse(updatedInst.plugins_config) : undefined,
    });
    await rebootInstance(updatedInst);
  }

  res.redirect(`/i/${encodeURIComponent(inst.slug)}`);
});

app.post("/i/:slug/whatsapp/qr/start", requireAuth, async (req, res) => {
  const session = (req as AuthedRequest).session;
  const inst = await getInstanceBySlug(String(req.params.slug || ""));
  if (!inst) return res.status(404).send("not found");
  if (!(await userHasInstanceAccess(session.userId, inst.id))) return res.status(403).send("forbidden");

  let out: { message?: string; qrDataUrl?: string } | null = null;
  let error: string | null = null;
  let alreadyConnected = false;

  try {
    // First check channel status to see if WhatsApp is in a good state
    const channelStatus = await withOpenClawClient(inst, (c) => c.channelsStatus());
    console.log(`[whatsapp/qr/start] Channel status for ${inst.slug}:`, JSON.stringify(channelStatus));

    // Check if WhatsApp is already connected
    const waStatus = channelStatus?.whatsapp || channelStatus?.channels?.whatsapp;
    if (waStatus?.connected || waStatus?.status === 'connected' || waStatus?.loggedIn) {
      alreadyConnected = true;
    } else {
      // Try to get QR code
      out = await withOpenClawClient(inst, (c) => c.whatsappQrStart(true));

      // Check if the response indicates already connected (no QR returned but no error)
      if (!out?.qrDataUrl && out?.message?.toLowerCase().includes('timed out')) {
        // After logout, may need container restart
        error = "WhatsApp session needs reinitialization. Please restart the container.";
      }
    }
  } catch (err: any) {
    console.error(`[whatsapp/qr/start] Error for ${inst.slug}:`, err);
    const errMsg = err.message || "";
    // "Timed out waiting for WhatsApp QR" likely means WhatsApp needs restart after logout
    if (errMsg.toLowerCase().includes('timed out') && errMsg.toLowerCase().includes('whatsapp')) {
      error = "WhatsApp session needs reinitialization. Please restart the container.";
    } else {
      error = errMsg || "Failed to connect to OpenClaw container";
    }
  }

  if (alreadyConnected) {
    res.send(
      page(
        `WhatsApp Connected - ${inst.slug}`,
        `
        <header class="container" style="padding-bottom: 0; border: none; margin-bottom: 1rem;">
          <nav aria-label="breadcrumb">
              <ul>
              <li><a href="/instances">Instances</a></li>
              <li><a href="/i/${encodeURIComponent(inst.slug)}">${escapeHtml(inst.slug)}</a></li>
              <li>WhatsApp</li>
              </ul>
          </nav>
          <h1>WhatsApp Already Connected</h1>
        </header>

        <article class="container" style="text-align: center;">
          <h2 style="color: var(--pico-ins-color);">Connected</h2>
          <p>WhatsApp is already linked to this instance. No QR code needed.</p>
          <p class="muted-text">If you want to reconnect with a different account, you'll need to log out from WhatsApp first.</p>
          <footer>
              <a role="button" href="/i/${encodeURIComponent(inst.slug)}">Back to Dashboard</a>
          </footer>
        </article>
      `,
      ),
    );
    return;
  }

  const qr = (out?.qrDataUrl as string | undefined) ?? null;
  res.send(
    page(
      `WhatsApp QR - ${inst.slug}`,
      `
      <header class="container" style="padding-bottom: 0; border: none; margin-bottom: 1rem;">
        <nav aria-label="breadcrumb">
            <ul>
            <li><a href="/instances">Instances</a></li>
            <li><a href="/i/${encodeURIComponent(inst.slug)}">${escapeHtml(inst.slug)}</a></li>
            <li>WhatsApp QR</li>
            </ul>
        </nav>
        <h1>Connect WhatsApp</h1>
      </header>

      <article class="container" style="text-align: center;">
        ${error
        ? `<div class="error-message" style="color: var(--pico-del-color); margin-bottom: 1rem;">
            <strong>Error:</strong> ${escapeHtml(error)}
           </div>
           <p><a href="/i/${encodeURIComponent(inst.slug)}">Back to Dashboard</a> |
              <a href="/i/${encodeURIComponent(inst.slug)}/restart" onclick="event.preventDefault(); fetch('/i/${encodeURIComponent(inst.slug)}/restart', {method:'POST'}).then(() => location.reload())">Try Restarting Container</a></p>`
        : `<div>${escapeHtml(String(out?.message ?? ""))}</div>
           ${qr
             ? `<div><img class="qr" src="${escapeHtml(qr)}" alt="WhatsApp QR" /></div>`
             : `<p class="muted-text">No QR code returned. Try restarting the container.</p>`
           }
           <footer>
               <small class="muted-text">Open WhatsApp on your phone → Settings → Linked Devices → Link a Device</small>
           </footer>`
        }
      </article>
    `,
    ),
  );
});

app.post("/i/:slug/whatsapp/qr/wait", requireAuth, async (req, res) => {
  const session = (req as AuthedRequest).session;
  const inst = await getInstanceBySlug(String(req.params.slug || ""));
  if (!inst) return res.status(404).send("not found");
  if (!(await userHasInstanceAccess(session.userId, inst.id))) return res.status(403).send("forbidden");

  let out: { message?: string; connected?: boolean } | null = null;
  let error: string | null = null;

  try {
    out = await withOpenClawClient(inst, (c) => c.whatsappQrWait());
    if (out?.connected) {
      await query("update instances set last_whatsapp_connected_at=now() where id=$1", [inst.id]);
    }
  } catch (err: any) {
    console.error(`[whatsapp/qr/wait] Error for ${inst.slug}:`, err);
    error = err.message || "Failed to connect to OpenClaw container";
  }

  res.send(
    page(
      `WhatsApp status - ${inst.slug}`,
      `
       <header class="container" style="padding-bottom: 0; border: none; margin-bottom: 1rem;">
         <nav aria-label="breadcrumb">
            <ul>
            <li><a href="/instances">Instances</a></li>
             <li><a href="/i/${encodeURIComponent(inst.slug)}">${escapeHtml(inst.slug)}</a></li>
            <li>WhatsApp Status</li>
            </ul>
        </nav>
         <h1>Connection Status</h1>
      </header>

      <article class="container">
        ${error
        ? `<div class="error-message" style="color: var(--pico-del-color); margin-bottom: 1rem;">
            <strong>Error:</strong> ${escapeHtml(error)}
           </div>`
        : `<hgroup>
            <h2>${out?.connected ? "Connected" : "Not Connected"}</h2>
            <p>${escapeHtml(String(out?.message ?? ""))}</p>
           </hgroup>`
        }
        <footer>
            <a role="button" href="/i/${encodeURIComponent(inst.slug)}">Back to Dashboard</a>
        </footer>
      </article>
    `,
    ),
  );
});

app.post("/i/:slug/power", requireAuth, async (req, res) => {
  const session = (req as AuthedRequest).session;
  const inst = await getInstanceBySlug(String(req.params.slug || ""));
  if (!inst) return res.status(404).send("not found");
  if (!(await userHasInstanceAccess(session.userId, inst.id))) return res.status(403).send("forbidden");
  const enabled = req.body?.enabled === "true";
  await query("update instances set power_user_enabled=$1, updated_at=now() where id=$2", [
    enabled,
    inst.id,
  ]);
  await updateOpenClawConfig({
    volumeName: inst.state_volume,
    slug: inst.slug,
    ownerE164: inst.owner_e164,
    defaultModel: inst.default_model,
    powerUserEnabled: enabled,
  });
  await rebootInstance(inst);
  res.redirect(`/i/${encodeURIComponent(inst.slug)}`);
});

app.get("/i/:slug/openclaw", requireAuth, async (req, res) => {
  const session = (req as AuthedRequest).session;
  const inst = await getInstanceBySlug(String(req.params.slug || ""));
  if (!inst) return res.status(404).send("not found");
  if (!(await userHasInstanceAccess(session.userId, inst.id))) return res.status(403).send("forbidden");
  if (!inst.power_user_enabled) return res.status(400).send("dashboard disabled");
  const secrets = await getInstanceSecrets(inst.id);
  const token = secrets.OPENCLAW_GATEWAY_TOKEN;
  if (!token) return res.status(500).send("missing gateway token");

  const dashUrl = `${config.baseUrl}/openclaw/${encodeURIComponent(inst.slug)}/?gatewayUrl=${encodeURIComponent(
    `${config.baseUrl.replace("http", "ws")}/openclaw/${inst.slug}`,
  )}#token=${encodeURIComponent(token)}`;
  res.redirect(dashUrl);
});

// Auth-gated proxy for OpenClaw dashboard (HTTP)
app.use("/openclaw/:slug", requireAuth, async (req, res, next) => {
  const session = (req as AuthedRequest).session;
  const slug = String(req.params.slug || "");
  const inst = await getInstanceBySlug(slug);
  if (!inst) return res.status(404).send("not found");
  if (!inst.power_user_enabled) return res.status(404).send("not found");
  if (!(await userHasInstanceAccess(session.userId, inst.id))) return res.status(403).send("forbidden");

  proxy.web(req, res, { target: `http://${inst.container_name}:18789` }, (err) => {
    next(err);
  });
});

// WS upgrades for /openclaw/:slug...
const server = http.createServer(app);
server.on("upgrade", async (req, socket, head) => {
  try {
    const url = new URL(req.url ?? "/", "http://localhost");
    const parts = url.pathname.split("/").filter(Boolean);
    if (parts[0] !== "openclaw" || !parts[1]) {
      socket.destroy();
      return;
    }
    const slug = parts[1];
    const cookies = (req.headers.cookie || "").split(";").reduce<Record<string, string>>((acc, kv) => {
      const [k, ...rest] = kv.trim().split("=");
      if (!k) return acc;
      acc[k] = decodeURIComponent(rest.join("=") || "");
      return acc;
    }, {});
    const token = cookies["nc_session"];
    // Minimal inline verify to avoid importing express middleware here.
    // If invalid, drop.
    if (!token) {
      socket.destroy();
      return;
    }
    // Reuse auth.ts verify via a dynamic import to keep logic centralized.
    const { verifySession } = await import("./auth.js");
    const session = verifySession(token);
    if (!session) {
      socket.destroy();
      return;
    }
    const inst = await getInstanceBySlug(slug);
    if (!inst || !inst.power_user_enabled) {
      socket.destroy();
      return;
    }
    if (!(await userHasInstanceAccess(session.userId, inst.id))) {
      socket.destroy();
      return;
    }
    proxy.ws(req, socket, head, { target: `ws://${inst.container_name}:18789` });
  } catch {
    socket.destroy();
  }
});

const port = 3000;
server.listen(port, () => {
  console.log(`nc-control listening on ${port}`);
  requireSslInProd();
});
