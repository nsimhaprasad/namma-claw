import WebSocket from "ws";
import { randomUUID } from "node:crypto";

type ResFrame = {
  type: "res";
  id: string;
  ok: boolean;
  payload?: unknown;
  error?: { code?: string; message?: string };
};

type EventFrame = {
  type: "event";
  event: string;
  payload?: unknown;
};

export class OpenClawWsClient {
  private ws: WebSocket;
  private pending = new Map<string, { resolve: (v: any) => void; reject: (e: any) => void }>();

  constructor(private url: string, private token: string) {
    this.ws = new WebSocket(url);
    this.ws.on("message", (data) => this.onMessage(String(data)));
    this.ws.on("close", () => this.failAll(new Error("gateway ws closed")));
    this.ws.on("error", () => {
      // close handler will trigger
    });
  }

  async ready(): Promise<void> {
    if (this.ws.readyState === WebSocket.OPEN) {
      return;
    }
    await new Promise<void>((resolve, reject) => {
      const onOpen = () => {
        cleanup();
        resolve();
      };
      const onErr = (err: unknown) => {
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

  private failAll(err: Error) {
    for (const [, p] of this.pending) {
      p.reject(err);
    }
    this.pending.clear();
  }

  private onMessage(raw: string) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return;
    }
    const frame = parsed as { type?: unknown };
    if (frame.type === "res") {
      const res = parsed as ResFrame;
      const pending = this.pending.get(res.id);
      if (!pending) return;
      this.pending.delete(res.id);
      if (res.ok) pending.resolve(res.payload);
      else pending.reject(new Error(res.error?.message || "request failed"));
      return;
    }
    if (frame.type === "event") {
      const evt = parsed as EventFrame;
      // For MVP we don't rely on connect.challenge because we disable device auth for our instances.
      // If this ever becomes required, implement the full challenge/nonce behavior.
      void evt;
      return;
    }
  }

  request<T = unknown>(method: string, params?: unknown): Promise<T> {
    const id = randomUUID();
    const frame = { type: "req", id, method, params };
    const p = new Promise<T>((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
    });
    this.ws.send(JSON.stringify(frame));
    return p;
  }

  async connect(): Promise<void> {
    await this.ready();
    await this.request("connect", {
      minProtocol: 3,
      maxProtocol: 3,
      client: {
        id: "openclaw-cli",
        version: "1.0.0",
        platform: "node",
      },
      role: "operator",
      scopes: ["operator.admin"],
      device: undefined,
      caps: [],
      auth: { token: this.token },
      userAgent: "nc-control/1.0",
      locale: "en-US",
    });
  }

  async whatsappQrStart(force: boolean): Promise<{ message?: string; qrDataUrl?: string }> {
    return await this.request("web.login.start", { force, timeoutMs: 30_000 });
  }

  async whatsappQrWait(): Promise<{ message?: string; connected?: boolean }> {
    return await this.request("web.login.wait", { timeoutMs: 120_000 });
  }
}

