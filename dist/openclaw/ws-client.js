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
    async ready() {
        if (this.ws.readyState === WebSocket.OPEN) {
            return;
        }
        await new Promise((resolve, reject) => {
            const onOpen = () => {
                cleanup();
                resolve();
            };
            const onErr = (err) => {
                cleanup();
                reject(err);
            };
            const cleanup = () => {
                this.ws.off("open", onOpen);
                this.ws.off("error", onErr);
            };
            this.ws.on("open", onOpen);
            this.ws.on("error", onErr);
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
    request(method, params) {
        const id = randomUUID();
        const frame = { type: "req", id, method, params };
        const p = new Promise((resolve, reject) => {
            this.pending.set(id, { resolve, reject });
        });
        this.ws.send(JSON.stringify(frame));
        return p;
    }
    async connect() {
        await this.ready();
        await this.request("connect", {
            minProtocol: 3,
            maxProtocol: 3,
            client: {
                id: "nc-web",
                version: "dev",
                platform: "server",
                mode: "webchat",
            },
            role: "operator",
            scopes: ["operator.admin"],
            device: undefined,
            caps: [],
            auth: { token: this.token },
            userAgent: "nc-web",
            locale: "en-US",
        });
    }
    async whatsappQrStart(force) {
        return await this.request("web.login.start", { force, timeoutMs: 30_000 });
    }
    async whatsappQrWait() {
        return await this.request("web.login.wait", { timeoutMs: 120_000 });
    }
}
