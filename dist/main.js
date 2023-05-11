"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Monban = void 0;
const uuid_1 = require("uuid");
const jwt = require("jsonwebtoken");
const cookie = require("cookie");
const hono_1 = require("hono");
__exportStar(require("./session"), exports);
__exportStar(require("./user"), exports);
class Monban {
    providers;
    sessionStore;
    userManager;
    secret;
    maxAge = 60 * 60 * 24 * 30;
    csrf = true;
    cookieOptions = {
        path: '/',
        sameSite: 'lax',
        secure: true,
        httpOnly: true,
    };
    constructor(providers, sessionStore, userManager, options) {
        this.providers = providers;
        this.sessionStore = sessionStore;
        this.userManager = userManager;
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
    async createUser(accountInfo) {
        const userId = await this.userManager.createUser(accountInfo);
        return userId;
    }
    async createToken(userId) {
        const sessionId = await this.sessionStore.create(userId);
        const payload = {
            sub: userId,
            sessionId: sessionId,
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
                userId: payload.sub,
            };
            return session;
        }
        return undefined;
    }
    async getSetCookie(userId) {
        let setCookie;
        if (userId === undefined) {
            setCookie = cookie.serialize('_monban_token', '', {
                ...this.cookieOptions,
                maxAge: 0,
            });
        }
        else {
            const token = await this.createToken(userId);
            setCookie = cookie.serialize('_monban_token', token, {
                ...this.cookieOptions,
                maxAge: this.maxAge,
            });
        }
        return setCookie;
    }
    async createCsrfToken() {
        const data = new TextEncoder().encode(`${(0, uuid_1.v4)()}${this.secret}`);
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
    async handleRequest(req, endpoint) {
        const app = new hono_1.Hono().basePath(endpoint);
        app.get('/login/:provider/*', async (c) => {
            const providerName = c.req.param('provider');
            const provider = this.providers[providerName];
            if (provider === undefined) {
                return c.json(undefined, 404);
            }
            const res = provider.handleLogin(c.req.raw, `${endpoint}/login/${providerName}`, this);
            return res;
        });
        app.get('/me', async (c) => {
            const session = await this.getSession(c.req.raw);
            if (session === undefined) {
                return c.json(undefined);
            }
            const user = await this.userManager.getUser(session.userId);
            await this.sessionStore.delete(session.id);
            const setCookie = await this.getSetCookie(session.userId);
            c.header('set-cookie', setCookie);
            return c.json(user);
        });
        app.get('/logout', async (c) => {
            const session = await this.getSession(c.req.raw);
            if (session !== undefined) {
                await this.sessionStore.delete(session.id);
            }
            const setCookie = await this.getSetCookie(undefined);
            c.header('set-cookie', setCookie);
            return c.json(undefined);
        });
        app.get('/delete', async (c) => {
            const session = await this.getSession(c.req.raw);
            if (session !== undefined) {
                await this.userManager.deleteUser(session.userId);
                await this.sessionStore.delete(session.id);
            }
            const setCookie = await this.getSetCookie(undefined);
            c.header('set-cookie', setCookie);
            return c.json(undefined);
        });
        app.get('/csrf', async (c) => {
            const { token, setCookie } = await this.createCsrfToken();
            c.header('set-cookie', setCookie);
            return c.json({
                token,
            });
        });
        const res = await app.fetch(req);
        return res;
    }
}
exports.Monban = Monban;
//# sourceMappingURL=main.js.map