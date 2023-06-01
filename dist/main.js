"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Monban = exports.Provider = void 0;
const cookie = require("cookie");
const hono_1 = require("hono");
const jwt = require("jsonwebtoken");
const uuid_1 = require("uuid");
class Provider {
}
exports.Provider = Provider;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
class Monban {
    providers;
    secret;
    maxAge = 60 * 60;
    csrf = true;
    callback;
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
        this.callback = options.callback;
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
        const session = await this.callback.createSession(profile, this.maxAge);
        return session;
    }
    async refreshSession(session) {
        if (this.callback.refreshSession !== undefined) {
            const newSession = await this.callback.refreshSession(session, this.maxAge);
            return newSession;
        }
        else {
            return session;
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
    async invalidateSession(session) {
        if (this.callback.invalidateSession !== undefined) {
            await this.callback.invalidateSession(session);
        }
    }
    async createSessionCookie(session) {
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
    async createCsrfToken() {
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
            const payload = await this.decodeToken(token);
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
                await this.invalidateSession(session);
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
            const newSession = await this.refreshSession(session);
            const setCookie = await this.createSessionCookie(newSession);
            c.header('set-cookie', setCookie);
            return c.json(newSession);
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