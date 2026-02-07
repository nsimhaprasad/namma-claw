import crypto from "node:crypto";
import { config } from "./config.js";

function loadMasterKey(): Buffer {
  const raw = config.masterKeyBase64;
  const buf = Buffer.from(raw, "base64");
  if (buf.length !== 32) {
    throw new Error("NC_MASTER_KEY_BASE64 must decode to 32 bytes");
  }
  return buf;
}

const MASTER_KEY = loadMasterKey();

// Simple, robust at-rest encryption for secrets.
// Format: v1:<base64(iv(12) + tag(16) + ciphertext)>
export function encryptSecret(plaintext: string): string {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", MASTER_KEY, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  const packed = Buffer.concat([iv, tag, ciphertext]).toString("base64");
  return `v1:${packed}`;
}

export function decryptSecret(packed: string): string {
  const trimmed = packed.trim();
  if (!trimmed.startsWith("v1:")) {
    throw new Error("unsupported secret encoding");
  }
  const buf = Buffer.from(trimmed.slice(3), "base64");
  if (buf.length < 12 + 16 + 1) {
    throw new Error("invalid secret encoding");
  }
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(12, 28);
  const ciphertext = buf.subarray(28);
  const decipher = crypto.createDecipheriv("aes-256-gcm", MASTER_KEY, iv);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
  return plaintext;
}

