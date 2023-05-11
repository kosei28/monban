"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Monban = exports.MemorySessionStore = exports.SessionStore = void 0;
const uuid_1 = require("uuid");
const jwt = require("jsonwebtoken");
const cookie = require("cookie");
class SessionStore {
}
exports.SessionStore = SessionStore;
class MemorySessionStore extends SessionStore {
    async create(userId) {
        const sessionId = (0, uuid_1.v4)();
        if (globalThis.session === undefined) {
            globalThis.session = {};
        }
        globalThis.session[sessionId] = userId;
        return sessionId;
    }
    async get(sessionId) {
        if (globalThis.session === undefined) {
            return undefined;
        }
        const userId = globalThis.session[sessionId];
        if (userId === undefined) {
            return undefined;
        }
        return userId;
    }
    async delete(sessionId) {
        if (globalThis.session !== undefined) {
            delete globalThis.session[sessionId];
        }
    }
}
exports.MemorySessionStore = MemorySessionStore;
class Monban {
    sessionStore;
    secret;
    maxAge = 60 * 60 * 24 * 30;
    allowOrigins = [];
    cookieOptions = {
        path: '/',
        sameSite: 'lax',
        secure: true,
        httpOnly: true,
    };
    constructor(sessionStore, options) {
        this.sessionStore = sessionStore;
        this.secret = options.secret;
        this.maxAge = options.maxAge ?? this.maxAge;
        this.allowOrigins = options.allowOrigins ?? this.allowOrigins;
        if (options.cookie !== undefined) {
            this.cookieOptions = {
                ...this.cookieOptions,
                ...options.cookie,
            };
        }
    }
    async createToken(user) {
        const sessionId = await this.sessionStore.create(user.id);
        const payload = {
            sub: user.id,
            sessionId: sessionId,
            user,
        };
        const token = jwt.sign(payload, this.secret, {
            algorithm: 'HS256',
            expiresIn: this.maxAge,
        });
        return token;
    }
    async decodeToken(token) {
        try {
            const payload = jwt.verify(token, this.secret, {
                algorithms: ['HS256'],
            });
            return payload;
        }
        catch (e) {
            return undefined;
        }
    }
    async verify(payload) {
        const userId = await this.sessionStore.get(payload.sessionId);
        if (userId !== undefined && userId === payload.sub) {
            const session = {
                id: payload.sessionId,
                user: payload.user,
            };
            return session;
        }
        return undefined;
    }
    async getSetCookie(user) {
        let setCookie;
        if (user === undefined) {
            setCookie = cookie.serialize('token', '', {
                path: this.cookieOptions.path,
                maxAge: 0,
            });
        }
        else {
            const token = await this.createToken(user);
            setCookie = cookie.serialize('token', token, {
                ...this.cookieOptions,
                maxAge: this.maxAge,
            });
        }
        return setCookie;
    }
    async getSession(req) {
        const allowOrigins = [new URL(req.url).origin, ...this.allowOrigins];
        const origin = req.headers.get('origin');
        if (req.method !== 'GET' && (origin === null || !allowOrigins.includes(origin))) {
            return undefined;
        }
        const cookieHeader = req.headers.get('cookie');
        const { token } = cookie.parse(cookieHeader ?? '');
        if (token === undefined) {
            return undefined;
        }
        else {
            const payload = await this.decodeToken(token);
            if (payload === undefined) {
                return undefined;
            }
            const session = await this.verify(payload);
            return session;
        }
    }
}
exports.Monban = Monban;
