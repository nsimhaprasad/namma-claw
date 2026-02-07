import WebSocket from "ws";
import { randomUUID } from "node:crypto";
export class OpenClawWsClient {
    url;
    token;
    ws;
    pending = new Map();
    constructor(url, token) {
        this.url = url;
        this.token = token;
        this.ws = new WebSocket(url);
        this.ws.on("message", (data) => this.onMessage(String(data)));
        this.ws.on("close", () => this.failAll(new Error("gateway ws closed")));
        this.ws.on("error", () => {
            // close handler will trigger
        });
    }
    async ready(timeoutMs = 10_000) {
        if (this.ws.readyState === WebSocket.OPEN) {
            return;
        }
        await new Promise((resolve, reject) => {
            const timeout = setTimeout(() => {
                cleanup();
                reject(new Error(`WebSocket connection timeout after ${timeoutMs}ms`));
            }, timeoutMs);
            const onOpen = () => {
                cleanup();
                resolve();
            };
            const onErr = (err) => {
                cleanup();
                reject(err instanceof Error ? err : new Error(`WebSocket error: ${String(err)}`));
            };
            const onClose = () => {
                cleanup();
                reject(new Error("WebSocket closed before connection established"));
            };
            const cleanup = () => {
                clearTimeout(timeout);
                this.ws.off("open", onOpen);
                this.ws.off("error", onErr);
                this.ws.off("close", onClose);
            };
            this.ws.on("open", onOpen);
            this.ws.on("error", onErr);
            this.ws.on("close", onClose);
        });
    }
    close() {
        this.ws.close();
    }
    failAll(err) {
        for (const [, p] of this.pending) {
            p.reject(err);
        }
        this.pending.clear();
    }
    onMessage(raw) {
        let parsed;
        try {
            parsed = JSON.parse(raw);
        }
        catch {
            return;
        }
        const frame = parsed;
        if (frame.type === "res") {
            const res = parsed;
            const pending = this.pending.get(res.id);
            if (!pending)
                return;
            this.pending.delete(res.id);
            if (res.ok)
                pending.resolve(res.payload);
            else
                pending.reject(new Error(res.error?.message || "request failed"));
            return;
        }
        if (frame.type === "event") {
            const evt = parsed;
            // For MVP we don't rely on connect.challenge because we disable device auth for our instances.
            // If this ever becomes required, implement the full challenge/nonce behavior.
            void evt;
            return;
        }
    }
    async request(req, timeoutMs = 60_000) {
        const id = randomUUID();
        const frame = { type: "req", id, method: req.method, params: req.params };
        const p = new Promise((resolve, reject) => {
            const timeout = setTimeout(() => {
                this.pending.delete(id);
                reject(new Error(`Request '${req.method}' timed out after ${timeoutMs}ms`));
            }, timeoutMs);
            this.pending.set(id, {
                resolve: (v) => {
                    clearTimeout(timeout);
                    resolve(v);
                },
                reject: (e) => {
                    clearTimeout(timeout);
                    reject(e);
                },
            });
        });
        this.ws.send(JSON.stringify(frame));
        return p;
    }
    async connect() {
        await this.ready();
        await this.request({
            method: "connect",
            params: {
                minProtocol: 3,
                maxProtocol: 3,
                client: {
                    id: "gateway-client",
                    mode: "backend",
                    version: "1.0.0",
                    platform: "node",
                },
                role: "operator",
                scopes: ["operator.admin"],
                auth: { token: this.token },
                userAgent: "nc-control/1.0",
                locale: "en-US",
            }
        });
    }
    async whatsappQrStart(force) {
        // Increase timeout to 60s for QR generation, and request timeout to 90s
        return await this.request({ method: "web.login.start", params: { force, timeoutMs: 60_000 } }, 90_000);
    }
    async whatsappQrWait() {
        return await this.request({ method: "web.login.wait", params: { timeoutMs: 120_000 } }, 150_000);
    }
    async channelsStatus() {
        return await this.request({ method: "channels.status", params: {} });
    }
    async whatsappLogout() {
        return await this.request({ method: "whatsapp.logout", params: {} }, 30_000);
    }
    async whatsappReconnect() {
        return await this.request({ method: "whatsapp.reconnect", params: {} }, 30_000);
    }
    // Initiate WhatsApp login flow (needed after logout)
    async channelsLogin(channel = "whatsapp") {
        return await this.request({ method: "channels.login", params: { channel } }, 30_000);
    }
    // Start WhatsApp channel
    async whatsappStart() {
        return await this.request({ method: "whatsapp.start", params: {} }, 30_000);
    }
}
