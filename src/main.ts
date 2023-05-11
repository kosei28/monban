import { v4 as uuidv4 } from 'uuid';
import * as jwt from 'jsonwebtoken';
import * as cookie from 'cookie';
import { Hono } from 'hono';

declare global {
    // eslint-disable-next-line no-var
    var monbanSession: { [id: string]: string } | undefined;
}

export type AccountInfoBase = {
    name: string;
    email: string;
    provider: string;
};

export type Providers<T extends AccountInfoBase> = { [name: string]: Provider<T> };

export type Session = {
    id: string;
    userId: string;
};

export type TokenPayloadInput = {
    sub: string;
    sessionId: string;
};

export type TokenPayload = TokenPayloadInput & {
    iat: number;
    exp: number;
};

export type SessionManagerOptions = {
    secret: string;
    maxAge?: number;
    csrf?: boolean;
    cookie?: cookie.CookieSerializeOptions;
};

export abstract class Provider<T extends AccountInfoBase> {
    abstract handleLogin(req: Request, endpoint: string, monban: Monban<T>): Promise<Response>;
}

export abstract class SessionStore {
    abstract create(userId: string): Promise<string>;
    abstract get(sessionId: string): Promise<string | undefined>;
    abstract delete(sessionId: string): Promise<void>;
}

export class MemorySessionStore extends SessionStore {
    async create(userId: string) {
        const sessionId = uuidv4();

        if (globalThis.monbanSession === undefined) {
            globalThis.monbanSession = {};
        }

        globalThis.monbanSession[sessionId] = userId;

        return sessionId;
    }

    async get(sessionId: string) {
        if (globalThis.monbanSession === undefined) {
            return undefined;
        }

        const userId = globalThis.monbanSession[sessionId];

        if (userId === undefined) {
            return undefined;
        }

        return userId;
    }

    async delete(sessionId: string) {
        if (globalThis.monbanSession !== undefined) {
            delete globalThis.monbanSession[sessionId];
        }
    }
}

export abstract class Monban<T extends AccountInfoBase> {
    protected providers: Providers<T>;
    protected sessionStore: MemorySessionStore;
    protected secret: string;
    protected maxAge = 60 * 60 * 24 * 30;
    protected csrf = true;
    protected cookieOptions: cookie.CookieSerializeOptions = {
        path: '/',
        sameSite: 'lax',
        secure: true,
        httpOnly: true,
    };

    constructor(providers: Providers<T>, sessionStore: MemorySessionStore, options: SessionManagerOptions) {
        this.providers = providers;
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

    abstract createUser(accountInfo: T): Promise<string>;

    abstract getUser(userId: string): Promise<object>;

    abstract deleteUser(userId: string): Promise<void>;

    async createToken(userId: string) {
        const sessionId = await this.sessionStore.create(userId);
        const payload: TokenPayloadInput = {
            sub: userId,
            sessionId: sessionId,
        };
        const token = jwt.sign(payload, this.secret, {
            algorithm: 'HS256',
            expiresIn: this.maxAge,
        });

        return token;
    }

    async decodeToken(token: string) {
        try {
            const payload = jwt.verify(token, this.secret, {
                algorithms: ['HS256'],
            }) as TokenPayload;

            return payload;
        } catch (e) {
            return undefined;
        }
    }

    async verify(payload: TokenPayloadInput) {
        const userId = await this.sessionStore.get(payload.sessionId);

        if (userId !== undefined && userId === payload.sub) {
            const session: Session = {
                id: payload.sessionId,
                userId: payload.sub,
            };

            return session;
        }

        return undefined;
    }

    async getSetCookie(userId: string | undefined) {
        let setCookie: string;

        if (userId === undefined) {
            setCookie = cookie.serialize('_monban_token', '', {
                ...this.cookieOptions,
                maxAge: 0,
            });
        } else {
            const token = await this.createToken(userId);
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

    async getSession(req: Request) {
        const csrfTokenHeader = req.headers.get('x-monban-csrf-token');
        const cookieHeader = req.headers.get('cookie');
        const { _monban_token: token, _monban_csrf_token: csrfToken } = cookie.parse(cookieHeader ?? '');

        if (req.method !== 'GET' && this.csrf && (csrfTokenHeader === null || csrfTokenHeader !== csrfToken)) {
            return undefined;
        }

        if (token === undefined) {
            return undefined;
        } else {
            const payload = await this.decodeToken(token);

            if (payload === undefined) {
                return undefined;
            }

            const session = await this.verify(payload);

            return session;
        }
    }

    async handleRequest(req: Request, endpoint: string) {
        const app = new Hono().basePath(endpoint);

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

            const user = await this.getUser(session.userId);

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
                await this.deleteUser(session.userId);
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
