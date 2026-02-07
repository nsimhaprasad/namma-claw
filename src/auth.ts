import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import type { Request, Response, NextFunction } from "express";
import { config } from "./config.js";

const COOKIE = "nc_session";

export type SessionClaims = {
  userId: string;
  email: string;
};

export function signSession(claims: SessionClaims): string {
  return jwt.sign(claims, config.jwtSecret, { expiresIn: "7d" });
}

export function verifySession(token: string): SessionClaims | null {
  try {
    const parsed = jwt.verify(token, config.jwtSecret);
    if (!parsed || typeof parsed !== "object") {
      return null;
    }
    const userId = (parsed as any).userId;
    const email = (parsed as any).email;
    if (typeof userId !== "string" || typeof email !== "string") {
      return null;
    }
    return { userId, email };
  } catch {
    return null;
  }
}

export async function hashPassword(password: string): Promise<string> {
  return await bcrypt.hash(password, 12);
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return await bcrypt.compare(password, hash);
}

export function setSessionCookie(res: Response, token: string) {
  res.cookie(COOKIE, token, {
    httpOnly: true,
    sameSite: "lax",
    secure: false, // set true behind HTTPS in production
    path: "/",
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
}

export function clearSessionCookie(res: Response) {
  res.clearCookie(COOKIE, { path: "/" });
}

export type AuthedRequest = Request & { session: SessionClaims };

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  const token = (req as any).cookies?.[COOKIE];
  const session = typeof token === "string" ? verifySession(token) : null;
  if (!session) {
    res.status(302).setHeader("Location", "/login");
    res.end();
    return;
  }
  (req as AuthedRequest).session = session;
  next();
}

