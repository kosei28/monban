"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Monban = exports.Provider = exports.Adapter = void 0;
const cookie = require("cookie");
const hono_1 = require("hono");
const jwt = require("jsonwebtoken");
const uuid_1 = require("uuid");
class Adapter {
}
exports.Adapter = Adapter;
class Provider {
}
exports.Provider = Provider;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
class Monban {
    providers;
    secret;
    maxAge = 60 * 60;
    csrf = true;
    adapter;
    callbacks;
    cookieOptions = {
        path: '/',
        sameSite: 'lax',
        secure: true,
        httpOnly: true,
    };
    constructor(providers, options) {
        this.providers = providers;
        this.secret = options.secret;
        this.maxAge = options.maxAge ?? this.maxAge;
        this.csrf = options.csrf ?? this.csrf;
        this.adapter = options.adapter;
        this.callbacks = options.callbacks;
        if (options.cookie !== undefined) {
            this.cookieOptions = {
                ...this.cookieOptions,
                ...options.cookie,
            };
        }
    }
    encodeToken(session) {
        const token = jwt.sign({
            sub: session.user.id,
            session: session,
        }, this.secret, {
            algorithm: 'HS256',
            expiresIn: this.maxAge,
        });
        return token;
    }
    decodeToken(token) {
        try {
            const session = jwt.verify(token, this.secret, {
                algorithms: ['HS256'],
            });
            return session;
        }
        catch (e) {
            return undefined;
        }
    }
    async createSession(profile) {
        const user = await this.callbacks.authenticate(profile);
        const session = {
            id: (0, uuid_1.v4)(),
            user,
        };
        if (this.adapter !== undefined) {
            await this.adapter.createSession(session, this.maxAge);
        }
        return session;
    }
    async verifySession(session) {
        if (this.adapter !== undefined) {
            const verified = await this.adapter.verifySession(session);
            return verified;
        }
        else {
            return true;
        }
    }
    async extendSession(session) {
        if (this.adapter !== undefined) {
            await this.adapter.extendSession(session);
        }
    }
    async invalidateSession(sessionId) {
        if (this.adapter !== undefined) {
            await this.adapter.invalidateSession(sessionId);
        }
    }
    async invalidateUserSessions(userId) {
        if (this.adapter !== undefined) {
            await this.adapter.invalidateUserSessions(userId);
        }
    }
    createSessionCookie(session) {
        let setCookie;
        if (session === undefined) {
            setCookie = cookie.serialize('_monban_token', '', {
                ...this.cookieOptions,
                maxAge: 0,
            });
        }
        else {
            const token = this.encodeToken(session);
            setCookie = cookie.serialize('_monban_token', token, {
                ...this.cookieOptions,
                maxAge: this.maxAge,
            });
        }
        return setCookie;
    }
    createCsrfToken() {
        const token = (0, uuid_1.v4)();
        const setCookie = cookie.serialize('_monban_csrf_token', token, {
            ...this.cookieOptions,
            maxAge: undefined,
            httpOnly: false,
        });
        return {
            token,
            setCookie,
        };
    }
    async isAuthenticated(req) {
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
            const payload = this.decodeToken(token);
            if (payload === undefined) {
                return undefined;
            }
            if (await this.verifySession(payload.session)) {
                return payload.session;
            }
            return undefined;
        }
    }
    async handleRequest(req, endpoint) {
        const app = new hono_1.Hono().basePath(endpoint);
        app.get('/providers/:provider/*', async (c) => {
            const providerName = c.req.param('provider');
            const provider = this.providers[providerName];
            if (provider === undefined) {
                return c.json(undefined, 404);
            }
            const res = provider.handleRequest(c.req.raw, `${endpoint}/providers/${providerName}`, this);
            return res;
        });
        app.get('/signout', async (c) => {
            const session = await this.isAuthenticated(c.req.raw);
            if (session !== undefined) {
                await this.invalidateSession(session.id);
            }
            const setCookie = await this.createSessionCookie(undefined);
            c.header('set-cookie', setCookie);
            return c.json(undefined);
        });
        app.get('/session', async (c) => {
            const session = await this.isAuthenticated(c.req.raw);
            if (session === undefined) {
                c.status(401);
                return c.json(undefined);
            }
            await this.extendSession(session);
            const setCookie = await this.createSessionCookie(session);
            c.header('set-cookie', setCookie);
            return c.json(session);
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