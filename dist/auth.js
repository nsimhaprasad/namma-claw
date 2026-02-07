import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { config } from "./config.js";
const COOKIE = "nc_session";
export function signSession(claims) {
    return jwt.sign(claims, config.jwtSecret, { expiresIn: "7d" });
}
export function verifySession(token) {
    try {
        const parsed = jwt.verify(token, config.jwtSecret);
        if (!parsed || typeof parsed !== "object") {
            return null;
        }
        const userId = parsed.userId;
        const email = parsed.email;
        if (typeof userId !== "string" || typeof email !== "string") {
            return null;
        }
        return { userId, email };
    }
    catch {
        return null;
    }
}
export async function hashPassword(password) {
    return await bcrypt.hash(password, 12);
}
export async function verifyPassword(password, hash) {
    return await bcrypt.compare(password, hash);
}
export function setSessionCookie(res, token) {
    res.cookie(COOKIE, token, {
        httpOnly: true,
        sameSite: "lax",
        secure: false, // set true behind HTTPS in production
        path: "/",
        maxAge: 7 * 24 * 60 * 60 * 1000,
    });
}
export function clearSessionCookie(res) {
    res.clearCookie(COOKIE, { path: "/" });
}
export function requireAuth(req, res, next) {
    const token = req.cookies?.[COOKIE];
    const session = typeof token === "string" ? verifySession(token) : null;
    if (!session) {
        res.status(302).setHeader("Location", "/login");
        res.end();
        return;
    }
    req.session = session;
    next();
}
