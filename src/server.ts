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
  createOpenClawInstance,
  restartOpenClawContainer,
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
  power_user_enabled: boolean;
};

const SlugSchema = z
  .string()
  .trim()
  .min(2)
  .max(32)
  .regex(/^[a-z][a-z0-9-]+$/, "slug must be dns-safe (a-z, 0-9, '-')");

const SecretKeyAllowlist = new Set<string>([
  // OpenClaw expected keys + common providers
  "OPENAI_API_KEY",
  "ANTHROPIC_API_KEY",
  "ANTHROPIC_OAUTH_TOKEN",
  "GEMINI_API_KEY",
  "ZAI_API_KEY",
  "OPENROUTER_API_KEY",
  "AI_GATEWAY_API_KEY",
  "MINIMAX_API_KEY",
  "SYNTHETIC_API_KEY",
  "DEEPGRAM_API_KEY",
]);

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
  // For production, set cookies secure=true and consider HSTS. Keep dev simple.
}

app.get("/", (req, res) => {
  res.redirect("/instances");
});

app.get("/signup", (_req, res) => {
  res.send(
    page(
      "Sign up",
      `
      <h1>nc.beskar.tech</h1>
      <div class="card">
        <form method="post" action="/signup">
          <div class="row"><label>Email <input name="email" type="email" required /></label></div>
          <div class="row"><label>Password <input name="password" type="password" required /></label></div>
          <div class="row"><button type="submit">Create account</button> <a href="/login">Login</a></div>
        </form>
      </div>
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
      <h1>nc.beskar.tech</h1>
      <div class="card">
        <form method="post" action="/login">
          <div class="row"><label>Email <input name="email" type="email" required /></label></div>
          <div class="row"><label>Password <input name="password" type="password" required /></label></div>
          <div class="row"><button type="submit">Login</button> <a href="/signup">Sign up</a></div>
        </form>
      </div>
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
      <div class="card">
        <div><b>${escapeHtml(i.slug)}</b> <span class="muted">(${escapeHtml(i.status)})</span></div>
        <div class="row">
          <a href="/i/${encodeURIComponent(i.slug)}">Open</a>
          ${
            i.power_user_enabled
              ? `<a href="/i/${encodeURIComponent(i.slug)}/openclaw">OpenClaw dashboard</a>`
              : `<span class="muted">dashboard disabled</span>`
          }
        </div>
      </div>
    `,
    )
    .join("\n");

  res.send(
    page(
      "Instances",
      `
      <div class="row" style="justify-content: space-between;">
        <h1>Instances</h1>
        <form method="post" action="/logout"><button type="submit">Logout</button></form>
      </div>
      <div class="card">
        <form method="post" action="/instances">
          <div class="row"><label>Slug <input name="slug" placeholder="simha" required /></label></div>
          <div class="row"><button type="submit">Create instance</button></div>
          <div class="muted">This provisions a per-user OpenClaw container on the server.</div>
        </form>
      </div>
      ${list || `<div class="muted">No instances yet.</div>`}
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

  // Create container. Start with no provider env; users can set keys later.
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

  res.send(
    page(
      `Instance ${inst.slug}`,
      `
      <div class="row" style="justify-content: space-between;">
        <h1>${escapeHtml(inst.slug)}</h1>
        <div class="row"><a href="/instances">Back</a></div>
      </div>

      <div class="card">
        <div><b>Status</b>: ${escapeHtml(inst.status)}</div>
        <form method="post" action="/i/${encodeURIComponent(inst.slug)}/restart">
          <button type="submit">Restart container</button>
        </form>
      </div>

      <div class="card">
        <h2>LLM keys</h2>
        <form method="post" action="/i/${encodeURIComponent(inst.slug)}/secrets">
          <div class="row">
            <label>Key
              <select name="key">
                ${Array.from(SecretKeyAllowlist)
                  .sort()
                  .map((k) => `<option value="${escapeHtml(k)}">${escapeHtml(k)}</option>`)
                  .join("")}
              </select>
            </label>
          </div>
          <div class="row"><label>Value <input name="value" type="password" required /></label></div>
          <div class="row"><button type="submit">Save</button></div>
          <div class="muted">Keys are encrypted at rest. Changing keys requires a restart.</div>
        </form>
        <form method="post" action="/i/${encodeURIComponent(inst.slug)}/model">
          <div class="row"><label>Default model <input name="defaultModel" placeholder="anthropic/claude-opus-4-6" /></label></div>
          <div class="row"><button type="submit">Set model</button></div>
        </form>
      </div>

      <div class="card">
        <h2>WhatsApp</h2>
        <form method="post" action="/i/${encodeURIComponent(inst.slug)}/owner">
          <div class="row"><label>Owner phone (E.164) <input name="ownerE164" placeholder="+15551234567" value="${escapeHtml(inst.owner_e164 || "")}" /></label></div>
          <div class="row"><button type="submit">Save owner number</button></div>
          <div class="muted">If set, DM policy becomes allowlist. If unset, DM policy is pairing.</div>
        </form>

        <div class="row">
          <form method="post" action="/i/${encodeURIComponent(inst.slug)}/whatsapp/qr/start">
            <button type="submit">Generate QR</button>
          </form>
          <form method="post" action="/i/${encodeURIComponent(inst.slug)}/whatsapp/qr/wait">
            <button type="submit">Wait for connection</button>
          </form>
        </div>

        <div id="qr" class="muted">Use the buttons above to show a QR code.</div>
      </div>

      <div class="card">
        <h2>Power user</h2>
        <form method="post" action="/i/${encodeURIComponent(inst.slug)}/power">
          <label>
            <input type="checkbox" name="enabled" value="true" ${inst.power_user_enabled ? "checked" : ""} />
            Enable OpenClaw dashboard
          </label>
          <div class="row"><button type="submit">Save</button></div>
        </form>
        ${
          inst.power_user_enabled
            ? `<div class="row"><a href="/i/${encodeURIComponent(inst.slug)}/openclaw">Open dashboard</a></div>`
            : `<div class="muted">Dashboard is disabled by default.</div>`
        }
      </div>
    `,
    ),
  );
});

app.post("/i/:slug/restart", requireAuth, async (req, res) => {
  const session = (req as AuthedRequest).session;
  const inst = await getInstanceBySlug(String(req.params.slug || ""));
  if (!inst) return res.status(404).send("not found");
  if (!(await userHasInstanceAccess(session.userId, inst.id))) return res.status(403).send("forbidden");
  await restartOpenClawContainer(inst.container_name);
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
  await restartOpenClawContainer(inst.container_name);
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
  await restartOpenClawContainer(inst.container_name);
  res.redirect(`/i/${encodeURIComponent(inst.slug)}`);
});

async function withOpenClawClient(inst: InstanceRow, fn: (c: OpenClawWsClient) => Promise<any>) {
  const secrets = await getInstanceSecrets(inst.id);
  const token = secrets.OPENCLAW_GATEWAY_TOKEN;
  if (!token) {
    throw new Error("missing gateway token secret");
  }
  const wsUrl = `ws://${inst.container_name}:18789/openclaw/${inst.slug}`;
  const client = new OpenClawWsClient(wsUrl, token);
  try {
    await client.connect();
    return await fn(client);
  } finally {
    client.close();
  }
}

app.post("/i/:slug/whatsapp/qr/start", requireAuth, async (req, res) => {
  const session = (req as AuthedRequest).session;
  const inst = await getInstanceBySlug(String(req.params.slug || ""));
  if (!inst) return res.status(404).send("not found");
  if (!(await userHasInstanceAccess(session.userId, inst.id))) return res.status(403).send("forbidden");

  const out = await withOpenClawClient(inst, (c) => c.whatsappQrStart(true));
  const qr = (out?.qrDataUrl as string | undefined) ?? null;
  res.send(
    page(
      `WhatsApp QR - ${inst.slug}`,
      `
      <div class="row" style="justify-content: space-between;">
        <h1>WhatsApp QR</h1>
        <a href="/i/${encodeURIComponent(inst.slug)}">Back</a>
      </div>
      <div class="card">
        <div>${escapeHtml(String(out?.message ?? ""))}</div>
        ${
          qr
            ? `<div><img class="qr" src="${escapeHtml(qr)}" alt="WhatsApp QR" /></div>`
            : `<div class="muted">No QR returned.</div>`
        }
        <div class="muted">Open WhatsApp on your phone: Linked Devices -> Link a device -> scan.</div>
      </div>
    `,
    ),
  );
});

app.post("/i/:slug/whatsapp/qr/wait", requireAuth, async (req, res) => {
  const session = (req as AuthedRequest).session;
  const inst = await getInstanceBySlug(String(req.params.slug || ""));
  if (!inst) return res.status(404).send("not found");
  if (!(await userHasInstanceAccess(session.userId, inst.id))) return res.status(403).send("forbidden");
  const out = await withOpenClawClient(inst, (c) => c.whatsappQrWait());
  if (out?.connected) {
    await query("update instances set last_whatsapp_connected_at=now() where id=$1", [inst.id]);
  }
  res.send(
    page(
      `WhatsApp status - ${inst.slug}`,
      `
      <div class="row" style="justify-content: space-between;">
        <h1>WhatsApp status</h1>
        <a href="/i/${encodeURIComponent(inst.slug)}">Back</a>
      </div>
      <div class="card">
        <div><b>Connected</b>: ${escapeHtml(String(Boolean(out?.connected)))}</div>
        <div>${escapeHtml(String(out?.message ?? ""))}</div>
      </div>
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
  await restartOpenClawContainer(inst.container_name);
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

