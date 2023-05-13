"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Monban = exports.Provider = void 0;
const uuid_1 = require("uuid");
const jwt = require("jsonwebtoken");
const cookie = require("cookie");
const hono_1 = require("hono");
class Provider {
}
exports.Provider = Provider;
class Monban {
    providers;
    secret;
    maxAge = 60 * 60;
    csrf = true;
    cookieOptions = {
        path: '/',
        sameSite: 'lax',
        secure: true,
        httpOnly: true,
    };
    callback = {};
    constructor(providers, options) {
        this.providers = providers;
        this.secret = options.secret;
        this.maxAge = options.maxAge ?? this.maxAge;
        this.csrf = options.csrf ?? this.csrf;
        this.callback = options.callback ?? this.callback;
        if (options.cookie !== undefined) {
            this.cookieOptions = {
                ...this.cookieOptions,
                ...options.cookie,
            };
        }
    }
    async createSession(accountInfo, userId) {
        if (this.callback.createSession !== undefined) {
            const session = await this.callback.createSession(accountInfo, userId, this.maxAge);
            return session;
        }
        else {
            const session = {
                id: undefined,
                user: {
                    id: userId,
                },
            };
            return session;
        }
    }
    async refreshSession(oldSession) {
        if (this.callback.refreshSession !== undefined) {
            const session = await this.callback.refreshSession(oldSession, this.maxAge);
            return session;
        }
        else {
            return oldSession;
        }
    }
    async verifySession(session) {
        if (this.callback.verifySession !== undefined) {
            const verified = await this.callback.verifySession(session);
            return verified;
        }
        else {
            return true;
        }
    }
    async deleteSession(session) {
        if (this.callback.deleteSession !== undefined) {
            await this.callback.deleteSession(session);
        }
    }
    async createUser(accountInfo) {
        if (this.callback.createUser !== undefined) {
            const userId = await this.callback.createUser(accountInfo);
            return userId;
        }
        else {
            const userId = (0, uuid_1.v4)();
            return userId;
        }
    }
    async getUser(userId) {
        if (this.callback.getUser !== undefined) {
            const user = await this.callback.getUser(userId);
            return user;
        }
        else {
            return undefined;
        }
    }
    async deleteUser(userId) {
        if (this.callback.deleteUser !== undefined) {
            await this.callback.deleteUser(userId);
        }
    }
    async createToken(session) {
        const payload = {
            sub: session.user.id,
            sessionId: session.id,
            user: session.user,
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
        const session = {
            id: payload.sessionId,
            user: payload.user,
        };
        if (await this.verifySession(session)) {
            return session;
        }
        else {
            return undefined;
        }
    }
    async getSetCookie(session) {
        let setCookie;
        if (session === undefined) {
            setCookie = cookie.serialize('_monban_token', '', {
                ...this.cookieOptions,
                maxAge: 0,
            });
        }
        else {
            const token = await this.createToken(session);
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
        app.get('/signin/:provider/*', async (c) => {
            const providerName = c.req.param('provider');
            const provider = this.providers[providerName];
            if (provider === undefined) {
                return c.json(undefined, 404);
            }
            const res = provider.handleSignIn(c.req.raw, `${endpoint}/signin/${providerName}`, this);
            return res;
        });
        app.get('/me/session', async (c) => {
            const session = await this.getSession(c.req.raw);
            if (session === undefined) {
                return c.json(undefined);
            }
            const newSession = await this.refreshSession(session);
            const setCookie = await this.getSetCookie(newSession);
            c.header('set-cookie', setCookie);
            return c.json(newSession);
        });
        app.get('/me/user', async (c) => {
            const session = await this.getSession(c.req.raw);
            if (session === undefined) {
                return c.json(undefined);
            }
            const user = await this.getUser(session.user.id);
            const newSession = await this.refreshSession(session);
            const setCookie = await this.getSetCookie(newSession);
            c.header('set-cookie', setCookie);
            return c.json(user);
        });
        app.get('/signout', async (c) => {
            const session = await this.getSession(c.req.raw);
            if (session?.id !== undefined) {
                await this.deleteSession(session);
            }
            const setCookie = await this.getSetCookie(undefined);
            c.header('set-cookie', setCookie);
            return c.json(undefined);
        });
        app.get('/delete', async (c) => {
            const session = await this.getSession(c.req.raw);
            if (session?.id !== undefined) {
                await this.deleteUser(session.user.id);
                await this.deleteSession(session);
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