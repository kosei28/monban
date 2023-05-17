import * as cookie from 'cookie';
import { Hono } from 'hono';
import * as jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';

export type SessionUser = {
    id: string;
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
    createToken?: (userId: string, authInfo: InferAuthInfo<U>, maxAge: number) => Promise<TokenPayloadInput<T>>;
    refreshToken?: (oldPayload: TokenPayload<T>, maxAge: number) => Promise<TokenPayloadInput<T>>;
    verifyToken?: (payload: TokenPayload<T>) => Promise<boolean>;
    invalidateToken?: (payload: TokenPayload<T>) => Promise<void>;
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

    encodeToken(payload: TokenPayloadInput<T>) {
        const token = jwt.sign(payload, this.secret, {
            algorithm: 'HS256',
            expiresIn: this.maxAge,
        });

        return token;
    }

    decodeToken(token: string) {
        try {
            const payload = jwt.verify(token, this.secret, {
                algorithms: ['HS256'],
            }) as TokenPayload<T>;

            return payload;
        } catch (e) {
            return undefined;
        }
    }

    async createToken(userId: string, authInfo: InferAuthInfo<U>) {
        if (this.callback.createToken !== undefined) {
            const payload = await this.callback.createToken(userId, authInfo, this.maxAge);

            return payload;
        } else {
            const payload: TokenPayloadInput<T> = {
                sub: userId,
                sessionId: undefined,
                user: {
                    id: userId,
                } as T,
            };

            return payload;
        }
    }

    async refreshToken(oldPayload: TokenPayload<T>) {
        if (this.callback.refreshToken !== undefined) {
            const payload = await this.callback.refreshToken(oldPayload, this.maxAge);

            return payload;
        } else {
            const payload: TokenPayloadInput<T> = {
                sub: oldPayload.sub,
                sessionId: oldPayload.sessionId,
                user: oldPayload.user,
            };

            return payload;
        }
    }

    async verifyToken(payload: TokenPayload<T>) {
        if (this.callback.verifyToken !== undefined) {
            const verified = await this.callback.verifyToken(payload);

            return verified;
        } else {
            return true;
        }
    }

    async invalidateToken(payload: TokenPayload<T>) {
        if (this.callback.invalidateToken !== undefined) {
            await this.callback.invalidateToken(payload);
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

    async getTokenSetCookie(token: string | undefined) {
        let setCookie: string;

        if (token === undefined) {
            setCookie = cookie.serialize('_monban_token', '', {
                ...this.cookieOptions,
                maxAge: 0,
            });
        } else {
            setCookie = cookie.serialize('_monban_token', token, {
                ...this.cookieOptions,
                maxAge: this.maxAge,
            });
        }

        return setCookie;
    }

    async createCsrfToken() {
        const token = uuidv4();
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

            if (payload !== undefined && (await this.verifyToken(payload))) {
                return payload;
            }

            return undefined;
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
            const payload = await this.getSession(c.req.raw);

            if (payload?.sessionId !== undefined) {
                await this.invalidateToken(payload);
            }

            const setCookie = await this.getTokenSetCookie(undefined);
            c.header('set-cookie', setCookie);

            return c.json(undefined);
        });

        app.get('/session', async (c) => {
            const payload = await this.getSession(c.req.raw);

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
