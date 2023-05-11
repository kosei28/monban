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
        if (globalThis.monbanSession === undefined) {
            globalThis.monbanSession = {};
        }
        globalThis.monbanSession[sessionId] = userId;
        return sessionId;
    }
    async get(sessionId) {
        if (globalThis.monbanSession === undefined) {
            return undefined;
        }
        const userId = globalThis.monbanSession[sessionId];
        if (userId === undefined) {
            return undefined;
        }
        return userId;
    }
    async delete(sessionId) {
        if (globalThis.monbanSession !== undefined) {
            delete globalThis.monbanSession[sessionId];
        }
    }
}
exports.MemorySessionStore = MemorySessionStore;
class Monban {
    sessionStore;
    secret;
    maxAge = 60 * 60 * 24 * 30;
    csrf = true;
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
        this.csrf = options.csrf ?? this.csrf;
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
            setCookie = cookie.serialize('_monban_token', '', {
                ...this.cookieOptions,
                maxAge: 0,
            });
        }
        else {
            const token = await this.createToken(user);
            setCookie = cookie.serialize('_monban_token', token, {
                ...this.cookieOptions,
                maxAge: this.maxAge,
            });
        }
        return setCookie;
    }
    async createCsrfToken() {
        const data = new TextEncoder().encode(`uuidv4()${this.secret}`);
        const hash = await crypto.subtle.digest('SHA-256', data);
        const token = Array.from(new Uint8Array(hash))
            .map((v) => v.toString(16).padStart(2, '0'))
            .join('');
        const setCookie = cookie.serialize('_monban_csrf_token', token, {
            ...this.cookieOptions,
            maxAge: undefined,
        });
        return {
            token,
            setCookie,
        };
    }
    async getSession(req) {
        const csrfTokenHeader = req.headers.get('x-monban-csrf-token');
        const cookieHeader = req.headers.get('cookie');
        const { _monban_token: token, _monban_csrf_token: csrfToken } = cookie.parse(cookieHeader ?? '');
        if (req.method !== 'GET' && this.csrf && (csrfTokenHeader === null || csrfTokenHeader !== csrfToken)) {
            return undefined;
        }
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
//# sourceMappingURL=main.js.map