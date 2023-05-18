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
    encodeToken(payload) {
        const token = jwt.sign(payload, this.secret, {
            algorithm: 'HS256',
            expiresIn: this.maxAge,
        });
        return token;
    }
    decodeToken(token) {
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
    async createToken(userId, authInfo) {
        if (this.callback.createToken !== undefined) {
            const payload = await this.callback.createToken(userId, authInfo, this.maxAge);
            return payload;
        }
        else {
            const payload = {
                sub: userId,
                sessionId: undefined,
                user: {
                    id: userId,
                },
            };
            return payload;
        }
    }
    async refreshToken(oldPayload) {
        if (this.callback.refreshToken !== undefined) {
            const payload = await this.callback.refreshToken(oldPayload, this.maxAge);
            return payload;
        }
        else {
            const payload = {
                sub: oldPayload.sub,
                sessionId: oldPayload.sessionId,
                user: oldPayload.user,
            };
            return payload;
        }
    }
    async verifyToken(payload) {
        if (this.callback.verifyToken !== undefined) {
            const verified = await this.callback.verifyToken(payload);
            return verified;
        }
        else {
            return true;
        }
    }
    async invalidateToken(payload) {
        if (this.callback.invalidateToken !== undefined) {
            await this.callback.invalidateToken(payload);
        }
    }
    async createAccount(authInfo) {
        if (this.callback.createAccount !== undefined) {
            const userId = await this.callback.createAccount(authInfo);
            return userId;
        }
        else {
            const userId = (0, uuid_1.v4)();
            return userId;
        }
    }
    async verifyUser(authInfo) {
        if (this.callback.verifyUser !== undefined) {
            const userId = await this.callback.verifyUser(authInfo);
            return userId;
        }
        else {
            return undefined;
        }
    }
    async getTokenSetCookie(token) {
        let setCookie;
        if (token === undefined) {
            setCookie = cookie.serialize('_monban_token', '', {
                ...this.cookieOptions,
                maxAge: 0,
            });
        }
        else {
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
            if (payload !== undefined && (await this.verifyToken(payload))) {
                return payload;
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
            const payload = await this.isAuthenticated(c.req.raw);
            if (payload?.sessionId !== undefined) {
                await this.invalidateToken(payload);
            }
            const setCookie = await this.getTokenSetCookie(undefined);
            c.header('set-cookie', setCookie);
            return c.json(undefined);
        });
        app.get('/session', async (c) => {
            const payload = await this.isAuthenticated(c.req.raw);
            if (payload === undefined) {
                return c.json(undefined);
            }
            const newPayload = await this.refreshToken(payload);
            const token = this.encodeToken(newPayload);
            const setCookie = await this.getTokenSetCookie(token);
            c.header('set-cookie', setCookie);
            return c.json(newPayload);
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