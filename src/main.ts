import * as cookie from 'cookie';
import { Hono } from 'hono';
import * as jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';

export type SessionUser = {
    id: string;
};

export type Session<T extends SessionUser> = {
    id?: string;
    user: T;
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type InferSessionUser<T> = T extends Monban<infer U, any> ? U : never;

export type AuthInfo = {
    provider: string;
};

export abstract class Provider<T extends AuthInfo> {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    abstract handleRequest(req: Request, endpoint: string, monban: Monban<any, Providers<T>>): Promise<Response>;
}

export type Providers<T extends AuthInfo> = { [name: string]: Provider<T> };

export type InferAuthInfo<T> = T extends Providers<infer U> ? U : never;

export type TokenPayloadInput<T extends SessionUser> = {
    sub: string;
    sessionId?: string;
    user: T;
};

export type TokenPayload<T extends SessionUser> = TokenPayloadInput<T> & {
    iat: number;
    exp: number;
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type MonbanCallback<T extends SessionUser, U extends Providers<any>> = {
    createSession?: (userId: string, authInfo: InferAuthInfo<U>, maxAge: number) => Promise<Session<T>>;
    refreshSession?: (oldSession: Session<T>, maxAge: number) => Promise<Session<T>>;
    verifySession?: (session: Session<T>) => Promise<boolean>;
    deleteSession?: (session: Session<T>) => Promise<void>;
    createAccount?: (authInfo: InferAuthInfo<U>) => Promise<string>;
    verifyUser?: (authInfo: InferAuthInfo<U>) => Promise<string | undefined>;
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type MonbanOptions<T extends SessionUser, U extends Providers<any>> = {
    secret: string;
    maxAge?: number;
    csrf?: boolean;
    cookie?: cookie.CookieSerializeOptions;
    callback?: MonbanCallback<T, U>;
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export class Monban<T extends SessionUser, U extends Providers<any>> {
    protected providers: U;
    protected secret: string;
    protected maxAge = 60 * 60;
    protected csrf = true;
    protected cookieOptions: cookie.CookieSerializeOptions = {
        path: '/',
        sameSite: 'lax',
        secure: true,
        httpOnly: true,
    };
    protected callback: MonbanCallback<T, U> = {};

    constructor(providers: U, options: MonbanOptions<T, U>) {
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

    async createSession(userId: string, authInfo: InferAuthInfo<U>) {
        if (this.callback.createSession !== undefined) {
            const session = await this.callback.createSession(userId, authInfo, this.maxAge);

            return session;
        } else {
            const session = {
                id: undefined,
                user: {
                    id: userId,
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

    async createAccount(authInfo: InferAuthInfo<U>) {
        if (this.callback.createAccount !== undefined) {
            const userId = await this.callback.createAccount(authInfo);

            return userId;
        } else {
            const userId = uuidv4();

            return userId;
        }
    }

    async verifyUser(authInfo: InferAuthInfo<U>) {
        if (this.callback.verifyUser !== undefined) {
            const userId = await this.callback.verifyUser(authInfo);

            return userId;
        } else {
            return undefined;
        }
    }

    async createToken(session: Session<T>) {
        const payload: TokenPayloadInput<T> = {
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
            }) as TokenPayload<T>;

            return payload;
        } catch (e) {
            return undefined;
        }
    }

    async verify(payload: TokenPayloadInput<T>) {
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
