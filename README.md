# nc-control (MVP)

This is the control-plane service for `nc.beskar.tech`.

It provisions one OpenClaw container per instance and provides:

- user login
- instance create/restart
- encrypted provider key storage (env var injection planned; restart after change)
- WhatsApp QR rendering via OpenClaw WS RPC (`web.login.start` / `web.login.wait`)
- **recommended**: auth-gated HTTP+WebSocket proxy for `/openclaw/<slug>/` (power-user dashboard)

## Dev quickstart

1. Start Postgres:

```bash
docker compose -f docker-compose.dev.yml up -d
```

2. Create `.env`:

```bash
cp .env.example .env
```

Generate a master key:

```bash
python3 - <<'PY'
import os,base64
print(base64.b64encode(os.urandom(32)).decode())
PY
```

3. Install deps + init DB:

```bash
# From repository root
npm install
npm run db:init
```

4. Run the server:

```bash
npm run dev
```

Open `http://127.0.0.1:3000`.

## Notes

- This service uses the official OpenClaw image from Docker Hub in `OPENCLAW_IMAGE` (default `openclaw/openclaw:latest`).
  The image will be pulled automatically on first run. You can also pin a specific version like `openclaw/openclaw:2026.1.24-1`.

- For production, do not mount Docker socket into an internet-facing app without hardening.
  For MVP, it’s acceptable, but you should isolate the provisioner later.

