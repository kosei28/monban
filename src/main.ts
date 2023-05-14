import { v4 as uuidv4 } from 'uuid';
import * as jwt from 'jsonwebtoken';
import * as cookie from 'cookie';
import { Hono } from 'hono';

export type SessionUserBase = {
    id: string;
};

export type Session<T extends SessionUserBase> = {
    id?: string;
    user: T;
};

export type UserBase = {
    id: string;
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type InferSessionUser<T> = T extends Monban<infer U, any, any> ? U : never;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type InferUser<T> = T extends Monban<any, infer U, any> ? U : never;

export type AccountInfoBase = {
    provider: string;
};

export abstract class Provider<T extends AccountInfoBase> {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    abstract handleSignIn(req: Request, endpoint: string, monban: Monban<any, any, T>): Promise<Response>;
}

export type Providers<T extends AccountInfoBase> = { [name: string]: Provider<T> };

export type InferAccountInfo<T> = T extends Providers<infer U> ? U : never;

export type TokenPayloadInput = {
    sub: string;
    sessionId?: string;
};

export type TokenPayload = TokenPayloadInput & {
    iat: number;
    exp: number;
};

export type MonbanCallback<T extends SessionUserBase, U extends UserBase, V extends AccountInfoBase> = {
    createSession?: (user: U, accountInfo: V, maxAge: number) => Promise<Session<T>>;
    refreshSession?: (oldSession: Session<T>, maxAge: number) => Promise<Session<T>>;
    verifySession?: (session: Session<T>) => Promise<boolean>;
    deleteSession?: (session: Session<T>) => Promise<void>;
    createUser?: (accountInfo: V) => Promise<U>;
    getUser?: (userId: string) => Promise<U | undefined>;
    deleteUser?: (userId: string) => Promise<void>;
};

export type MonbanOptions<T extends SessionUserBase, U extends UserBase, V extends AccountInfoBase> = {
    secret: string;
    maxAge?: number;
    csrf?: boolean;
    cookie?: cookie.CookieSerializeOptions;
    callback?: MonbanCallback<T, U, V>;
};

export class Monban<T extends SessionUserBase, U extends UserBase, V extends AccountInfoBase> {
    protected providers: Providers<V>;
    protected secret: string;
    protected maxAge = 60 * 60;
    protected csrf = true;
    protected cookieOptions: cookie.CookieSerializeOptions = {
        path: '/',
        sameSite: 'lax',
        secure: true,
        httpOnly: true,
    };
    protected callback: MonbanCallback<T, U, V> = {};

    constructor(providers: Providers<V>, options: MonbanOptions<T, U, V>) {
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

    async createSession(user: U, accountInfo: V) {
        if (this.callback.createSession !== undefined) {
            const session = await this.callback.createSession(user, accountInfo, this.maxAge);

            return session;
        } else {
            const session = {
                id: undefined,
                user: {
                    id: user.id,
                },
            } as Session<T>;

            return session;
        }
    }

    async refreshSession(oldSession: Session<T>) {
        if (this.callback.refreshSession !== undefined) {
            const session = await this.callback.refreshSession(oldSession, this.maxAge);

            return session;
        } else {
            return oldSession;
        }
    }

    async verifySession(session: Session<T>) {
        if (this.callback.verifySession !== undefined) {
            const verified = await this.callback.verifySession(session);

            return verified;
        } else {
            return true;
        }
    }

    async deleteSession(session: Session<T>) {
        if (this.callback.deleteSession !== undefined) {
            await this.callback.deleteSession(session);
        }
    }

    async createUser(accountInfo: V) {
        if (this.callback.createUser !== undefined) {
            const user = await this.callback.createUser(accountInfo);

            return user;
        } else {
            const user = {
                id: uuidv4(),
            };

            return user;
        }
    }

    async getUser(userId: string) {
        if (this.callback.getUser !== undefined) {
            const user = await this.callback.getUser(userId);

            return user;
        } else {
            return undefined;
        }
    }

    async deleteUser(userId: string) {
        if (this.callback.deleteUser !== undefined) {
            await this.callback.deleteUser(userId);
        }
    }

    async createToken(session: Session<T>) {
        const payload: TokenPayloadInput & { user: T } = {
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

    async decodeToken(token: string) {
        try {
            const payload = jwt.verify(token, this.secret, {
                algorithms: ['HS256'],
            }) as TokenPayload & { user: T };

            return payload;
        } catch (e) {
            return undefined;
        }
    }

    async verify(payload: TokenPayloadInput & { user: T }) {
        const session = {
            id: payload.sessionId,
            user: payload.user,
        } as Session<T>;

        if (await this.verifySession(session)) {
            return session;
        } else {
            return undefined;
        }
    }

    async getSetCookie(session: Session<T> | undefined) {
        let setCookie: string;

        if (session === undefined) {
            setCookie = cookie.serialize('_monban_token', '', {
                ...this.cookieOptions,
                maxAge: 0,
            });
        } else {
            const token = await this.createToken(session);
            setCookie = cookie.serialize('_monban_token', token, {
                ...this.cookieOptions,
                maxAge: this.maxAge,
            });
        }

        return setCookie;
    }

    async createCsrfToken() {
        const data = new TextEncoder().encode(`${uuidv4()}${this.secret}`);
        const hash = await crypto.subtle.digest('SHA-256', data);
        const token = Array.from(new Uint8Array(hash))
            .map((v) => v.toString(16).padStart(2, '0'))
            .join('');
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

        app.get('/signin/:provider/*', async (c) => {
            const providerName = c.req.param('provider');
            const provider = this.providers[providerName];

            if (provider === undefined) {
                return c.json(undefined, 404);
            }

            const res = provider.handleSignIn(c.req.raw, `${endpoint}/signin/${providerName}`, this);

            return res;
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

        app.get('/session', async (c) => {
            const session = await this.getSession(c.req.raw);

            if (session === undefined) {
                return c.json(undefined);
            }

            const newSession = await this.refreshSession(session);
            const setCookie = await this.getSetCookie(newSession);
            c.header('set-cookie', setCookie);

            return c.json(newSession);
        });

        app.get('/user', async (c) => {
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
