# Managed OpenClaw (Per-User) Service Plan

Repo/workspace: `/Users/simhaprasad/Documents/workstation/beskar/namma-openclaw`  
Upstream OpenClaw reference: `/Users/simhaprasad/Documents/workstation/beskar/namma-openclaw/openclaw-upstream` @ commit `cde29fef7` (2026-02-07)

## Goal

Host a service at `https://nc.beskar.tech` that provisions **one isolated OpenClaw Gateway container per user** and makes it “WhatsApp-ready” with minimal setup:

- User creates their own OpenClaw instance (container + persistent state).
- User configures LLM provider keys (support many).
- User connects WhatsApp by scanning a QR code shown directly in *your* product UI.
- After WhatsApp is connected, the user can chat with their OpenClaw assistant via WhatsApp without installing anything locally.

## Key Constraints From OpenClaw

1. OpenClaw Gateway serves HTTP + WebSocket on one port (default `18789`) and the browser Control UI is an **admin surface**.
2. WhatsApp login QR is available via Gateway WebSocket RPC:
   - `web.login.start` returns `{ message?, qrDataUrl? }`
   - `web.login.wait` returns `{ message?, connected? }`
   Source: `openclaw-upstream/src/gateway/server-methods/web.ts`
3. OpenClaw loads provider keys from process env; config `env` block is non-overriding and supports `${VAR}` substitution.
   Source: `openclaw-upstream/docs/environment.md`

## Design Decisions (MVP)

### A) URL shape
Use **path-based** instance addressing for MVP (simplest DNS/TLS):

- Product: `https://nc.beskar.tech`
- Instance page: `https://nc.beskar.tech/i/<instanceSlug>` (this is your UI page, not OpenClaw’s admin UI)

Why: no wildcard DNS, no per-tenant router rules, one cert.

Optional later: subdomains (`https://<slug>.nc.beskar.tech`) via wildcard cert + wildcard DNS.

### B) Default: Don’t expose OpenClaw Control UI publicly
By default, your product renders only what’s needed:

- WhatsApp QR + connection status
- minimal “LLM provider key” configuration
- a small “health/status” view

OpenClaw Gateway port is **internal-only** (reachable only from the control-plane over a private Docker network).

Why: OpenClaw Control UI can modify config, run tools, etc. It’s not intended as a public multi-tenant surface.

### C) Optional: “Power user” mode exposes OpenClaw Control UI
Some users will want to operate OpenClaw directly (agents, config, logs, etc.). Provide a per-instance toggle:

- **Standard mode (default):** your UI shows provider setup + WhatsApp QR only.
- **Power user mode:** expose the OpenClaw Control UI for that instance at a dedicated path on `nc.beskar.tech`.

MVP approach (simple, no wildcard DNS):

- Expose dashboard at: `https://nc.beskar.tech/openclaw/<slug>/`
- The browser UI must connect its WebSocket to the *same path* so routing hits the right instance:
  - Use URL param support in OpenClaw UI: `?gatewayUrl=wss://nc.beskar.tech/openclaw/<slug>#token=<OPENCLAW_GATEWAY_TOKEN>`
  - Token should be in the URL fragment (`#token=...`) to avoid server access logs.

Important practical note:

- OpenClaw’s UI stores `gatewayUrl` and `token` in `localStorage` under a fixed key (`openclaw.control.settings.v1`) scoped to the origin. If one browser uses multiple instances on the same origin, the last-used instance can overwrite settings. For MVP, accept this; later you can move power-user dashboards to per-instance subdomains to isolate storage.

### D) Container-per-user (strong tenant separation)
Each user gets:

- 1 OpenClaw container
- 1 persistent volume for OpenClaw state (`OPENCLAW_STATE_DIR`)
- resource limits (CPU/mem/pids) to prevent noisy-neighbor

## High-Level Architecture (Single Server MVP)

Components on one VM:

1. **nc-web (control plane)**: your web UI + API (auth, instance mgmt, QR rendering).
2. **nc-provisioner**: internal module/service that can create/stop/restart containers (Docker API).
3. **Postgres**: users, instances, encrypted secrets, audit logs.
4. **Reverse proxy**: Caddy or Traefik for `nc.beskar.tech` TLS termination (only for nc-web).
5. **Docker Engine**: runs OpenClaw containers.

Network:

- `nc-web` and all `openclaw-<id>` containers join a private network `nc-internal`.
- No OpenClaw ports are published to host. `nc-web` reaches them by container DNS name on `nc-internal`.

## Data Model (Postgres)

Tables (minimum):

### `users`
- `id` (uuid)
- `email` (unique)
- `created_at`

### `instances`
- `id` (uuid)
- `user_id` (fk users)
- `slug` (unique, e.g. "simha")
- `status` enum: `creating|running|stopped|error`
- `container_name` (e.g. `openclaw_<id>`)
- `state_volume` (e.g. `openclaw_state_<id>`)
- `created_at`, `updated_at`
- `last_health_at`
- `last_whatsapp_connected_at`

### `instance_secrets`
Store provider keys and any other secret values.

- `id` (uuid)
- `instance_id` (fk instances)
- `key` (string, e.g. `OPENAI_API_KEY`)
- `ciphertext` (bytes)
- `created_at`, `updated_at`

### `audit_log`
- `id` (uuid)
- `user_id` (nullable)
- `instance_id` (nullable)
- `action` (string)
- `meta` (json)
- `created_at`

## Secrets Handling (Required)

Use envelope encryption:

- `NC_MASTER_KEY` on server (env var; later KMS).
- For each secret: generate random `dataKey`, encrypt secret with dataKey, encrypt dataKey with master key.
- Store ciphertext + encrypted dataKey in DB.

Never show full secrets after save. Provide “replace key” only.

## LLM Provider Key Support (MVP)

Support “many auth keys” by allowing a curated allowlist of environment variables to be set per instance.

Initial allowlist (aligns with OpenClaw expected keys list from `openclaw-upstream/src/config/io.ts` plus commonly used provider keys):

- LLM: `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `ANTHROPIC_OAUTH_TOKEN`, `GEMINI_API_KEY`, `OPENROUTER_API_KEY`, `ZAI_API_KEY`, `QWEN_API_KEY` (if present in docs), `AI_GATEWAY_API_KEY`, `MINIMAX_API_KEY`, `SYNTHETIC_API_KEY`
- Optional: transcription `DEEPGRAM_API_KEY`
- Channel tokens (not needed for WhatsApp-web, but future): `TELEGRAM_BOT_TOKEN`, `DISCORD_BOT_TOKEN`, `SLACK_BOT_TOKEN`, `SLACK_APP_TOKEN`

Implementation rule:

- Store these in `instance_secrets`.
- On container start, inject them as process env vars.

Model selection:

- In instance config, set default `agents.defaults.model.primary` to a provider/model string (ex: `openai/gpt-5.1-codex`, `anthropic/claude-opus-4-6`).
- UI: dropdown list of “provider defaults” + freeform override.

## OpenClaw Container Contract

### Image
Build a pinned image from upstream commit/tag and push to your registry (recommended).

- Tag format: `ghcr.io/<you>/openclaw:<upstreamCommit>`
- Rebuild only when you intentionally update OpenClaw.

### Runtime env vars per container
Minimum:

- `OPENCLAW_GATEWAY_TOKEN` = per-instance random token
- `OPENCLAW_STATE_DIR` = `/data/.openclaw`
- `OPENCLAW_WORKSPACE_DIR` = `/data/workspace`
- Provider keys (from `instance_secrets`) as env vars

### Persistent storage
One volume mounted at `/data` (or separate volumes if preferred).

Paths to persist:

- `${OPENCLAW_STATE_DIR}` (credentials, WhatsApp `creds.json`, config)
- `${OPENCLAW_WORKSPACE_DIR}` (optional, but aligns with OpenClaw expectations)

### Port / binding
Inside container:

- Gateway listens on `0.0.0.0:18789` (OpenClaw bind mode “lan”).
- Do not publish to host.

### Config file
Write a minimal config into `${OPENCLAW_STATE_DIR}/openclaw.json` before first start.

Recommended config for this product:

```json5
{
  // Minimize exposed surfaces; users do not access OpenClaw UI directly.
  gateway: {
    bind: "lan",
    auth: { mode: "token", token: "${OPENCLAW_GATEWAY_TOKEN}" },

    // Important: lets nc-web connect without browser-style device identity/pairing.
    controlUi: { enabled: false, dangerouslyDisableDeviceAuth: true },
  },

  // Enable WhatsApp channel; defaults dmPolicy to pairing if not set.
  channels: {
    whatsapp: {
      dmPolicy: "allowlist",
      allowFrom: ["${NC_OWNER_E164}"]
    }
  }
}
```

Notes:

- `NC_OWNER_E164` is the phone number (E.164) the user will message *from*.
  Your UI should ask for it during onboarding so WhatsApp replies aren’t gated by pairing.
- If you want “anyone can DM this WhatsApp account”, use `dmPolicy: "open"` and `allowFrom: ["*"]` (not recommended without abuse controls).

### Power user config override (when dashboardEnabled=true)
When a user enables the OpenClaw dashboard, write/patch config to:

```json5
{
  gateway: {
    controlUi: {
      enabled: true,
      basePath: "/openclaw/${NC_INSTANCE_SLUG}",

      // Keep this true unless you also implement full device-pairing UX.
      // Without it, users will hit “1008 pairing required” and need CLI approval.
      dangerouslyDisableDeviceAuth: true,
    },
  },
}
```

And expose the container with a reverse-proxy route:

- `Host("nc.beskar.tech") && PathPrefix("/openclaw/<slug>") -> openclaw_<id>:18789`

This requires your reverse proxy to support both HTTP and WebSocket upgrades on that path.

If you later want stronger security than “random token in a link”, implement an auth-gated proxy in `nc-web` (session cookie required) that forwards HTTP+WS to the instance, so the dashboard is not reachable without logging into `nc.beskar.tech`.

## Control Plane API (nc-web)

### Public endpoints

- `POST /api/signup|login` (your auth choice)
- `POST /api/instances` create an instance
- `GET /api/instances/:slug` instance view model (status, last connected, etc.)
- `PUT /api/instances/:slug/llm` set provider keys + default model
- `PUT /api/instances/:slug/whatsapp/owner` set `NC_OWNER_E164` and apply config

### WhatsApp QR endpoints (core UX)

- `POST /api/instances/:slug/whatsapp/qr/start`
  - server opens WS to the instance gateway and calls `connect`, then `web.login.start`
  - returns `{ qrDataUrl, message }`

- `POST /api/instances/:slug/whatsapp/qr/wait`
  - calls `web.login.wait` (long poll with timeout)
  - returns `{ connected, message }`

Optionally combine into one endpoint with server-sent events (SSE) that:
- emits QR
- emits “connected”

### Internal instance ops

- `POST /api/instances/:slug/restart`
- `POST /api/instances/:slug/stop`
- `POST /api/instances/:slug/start`
- `GET /api/instances/:slug/health` (calls OpenClaw `health` method or `/health` HTTP if enabled)

## Gateway WebSocket Client (nc-web)

Implement a minimal WS client compatible with OpenClaw’s “connect” flow.

Protocol sketch:

1. `ws = new WebSocket("ws://openclaw_<id>:18789")`
2. On open, send a `connect` request frame:
   - `minProtocol=3`, `maxProtocol=3`
   - `client`: `{ id: "nc-web", version: "<git>", platform: "server", mode: "webchat" }`
   - `role="operator"`, `scopes=[...]` (you can keep scopes minimal)
   - `device` omitted (because `dangerouslyDisableDeviceAuth=true`)
   - `auth: { token: OPENCLAW_GATEWAY_TOKEN }`
3. Then call `web.login.start` / `web.login.wait`

Reference implementation for browser is in:
`openclaw-upstream/ui/src/ui/gateway.ts` (do not copy device-identity parts; you don’t need them).

## UI Pages (nc-web)

### 1) Landing
- Login/signup

### 2) Instance page: `/i/<slug>`
This is the “WhatsApp-ready dashboard” (your product’s core page).

Sections:

- Status: running/stopped + restart
- LLM setup:
  - provider dropdown (OpenAI/Anthropic/OpenRouter/etc)
  - secret input (masked)
  - default model (prefill a sane default per provider)
- WhatsApp:
  - input: “Owner phone number (E.164)” (explains it’s the number you will DM from)
  - button: “Generate QR”
  - QR image (from `qrDataUrl`)
  - button: “I scanned it” (calls wait/poll)
  - status: connected / not connected
- “Test”:
  - show instructions: “Open WhatsApp, message the linked account from your owner number”

### 3) Power user page (optional): `/i/<slug>/advanced`
Contains:

- Toggle: “Expose OpenClaw dashboard”
- Button: “Open OpenClaw dashboard”
  - Link template:
    - `https://nc.beskar.tech/openclaw/<slug>/?gatewayUrl=wss://nc.beskar.tech/openclaw/<slug>#token=<OPENCLAW_GATEWAY_TOKEN>`
  - If you don’t want to reveal the gateway token in the page HTML, have `nc-web` generate a short-lived, one-time “dashboard link token” that maps to the real gateway token server-side and redirects to the final fragment URL.

## Provisioning / Lifecycle Details

### Create instance

Algorithm:

1. Validate `slug` (dns-safe for future subdomain use).
2. Insert instance in DB (`creating`).
3. Create Docker volume `openclaw_state_<instanceId>`.
4. Start container with:
   - name `openclaw_<instanceId>`
   - volume mounted at `/data`
   - env vars including gateway token and provider keys (if any)
   - join network `nc-internal`
5. Write config file into volume:
   - Easiest: start a short “init” container that mounts the same volume and writes `/data/.openclaw/openclaw.json`.
   - Alternative: `docker cp` a file into a running container and move it into place.
6. Mark instance `running`.

### Update config (owner phone / model)

Preferred: write config file and restart container.

Why: avoids building a deep dependency on OpenClaw config RPC semantics; restart is simpler and predictable for MVP.

### Health checks

- Periodically call OpenClaw health endpoint (OpenClaw Render config uses `/health`; confirm whether it’s enabled by default in your chosen run command).
- Record `last_health_at` + status transitions.

## Abuse Controls / Safety (Minimum for “open internet”)

Even if you don’t expose OpenClaw publicly, WhatsApp-connected agents can be abused.

Implement:

- Per-user rate limits on QR generation (`web.login.start`) and instance create.
- Instance cap per user (ex: 1 by default).
- CPU/mem limits per container.
- Idle shutdown policy (optional): if WhatsApp not connected for N hours, stop instance.
- Audit log for all secrets writes + instance ops.

## Deployment Checklist (Single VM)

1. Provision VM (Ubuntu recommended) with:
   - Docker Engine + Compose v2
   - Postgres
   - Caddy/Traefik for TLS
2. DNS:
   - `A/AAAA` record: `nc.beskar.tech -> VM IP`
3. Run `nc-web` behind TLS at `https://nc.beskar.tech`
4. Create docker network `nc-internal`
5. Ensure `nc-web` can reach Docker API (either run on host, or mount `/var/run/docker.sock` with strong hardening).
6. Ensure OpenClaw image is available locally (pulled from registry).

## Milestones

### Milestone 1: Skeleton (1-2 days)
- DB schema + migrations
- User auth
- Instance create/start/stop/restart (no WhatsApp yet)

### Milestone 2: WhatsApp QR MVP (2-4 days)
- Implement WS client `connect` + `web.login.start` + `web.login.wait`
- Instance page renders QR and shows connected status

### Milestone 3: Provider keys + model defaults (2-4 days)
- Secrets storage + env injection on container start
- UI for provider selection + save
- Restart instance to apply

### Milestone 4: Hardening (2-5 days)
- rate limiting, audit logging, resource limits
- monitoring + alerts (container restarts, disk use)

## Future Enhancements

- Subdomains (`<slug>.nc.beskar.tech`) with wildcard DNS + wildcard TLS.
- Multi-host scheduling (k8s/nomad) once one VM fills up.
- Expose a *read-only* OpenClaw view (selected RPCs only), never the full admin UI.
- “Open” DM policy with safety rails (captcha-like pairing flow in your UI, throttling, ban list).
