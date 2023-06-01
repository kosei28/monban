import * as cookie from 'cookie';
import { Hono } from 'hono';
import * as jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';

export type Profile = {
    provider: string;
};

export abstract class Provider<T extends Profile> {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    abstract handleRequest(req: Request, endpoint: string, monban: Monban<Providers<T>>): Promise<Response>;
}

export type Providers<T extends Profile> = { [name: string]: Provider<T> };

export type InferProfile<T> = T extends Providers<infer U> ? U : never;

export type Session = {
    id: string;
    userId: string;
};

export type TokenPayload = {
    sub: string;
    sessionId: string;
    iat: number;
    exp: number;
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type MonbanCallback<T extends Providers<any>> = {
    createSession?: (userId: string, maxAge: number) => Promise<Session>;
    refreshSession?: (session: Session, maxAge: number) => Promise<Session>;
    verifySession?: (session: Session) => Promise<boolean>;
    invalidateSession?: (session: Session) => Promise<void>;
    createUser?: (profile: InferProfile<T>) => Promise<string>;
    verifyUser?: (profile: InferProfile<T>) => Promise<string | undefined>;
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type MonbanOptions<T extends Providers<any>> = {
    secret: string;
    maxAge?: number;
    csrf?: boolean;
    cookie?: cookie.CookieSerializeOptions;
    callback?: MonbanCallback<T>;
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export class Monban<T extends Providers<any>> {
    protected providers: T;
    protected secret: string;
    protected maxAge = 60 * 60;
    protected csrf = true;
    protected callback: MonbanCallback<T> = {};

    cookieOptions: cookie.CookieSerializeOptions = {
        path: '/',
        sameSite: 'lax',
        secure: true,
        httpOnly: true,
    };

    constructor(providers: T, options: MonbanOptions<T>) {
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

    encodeToken(session: Session) {
        const token = jwt.sign(
            {
                sub: session.userId,
                sessionId: session.id,
            },
            this.secret,
            {
                algorithm: 'HS256',
                expiresIn: this.maxAge,
            },
        );

        return token;
    }

    decodeToken(token: string) {
        try {
            const session = jwt.verify(token, this.secret, {
                algorithms: ['HS256'],
            }) as TokenPayload;

            return session;
        } catch (e) {
            return undefined;
        }
    }

    async createSession(userId: string) {
        if (this.callback.createSession !== undefined) {
            const session = await this.callback.createSession(userId, this.maxAge);

            return session;
        } else {
            const session: Session = {
                id: uuidv4(),
                userId,
            };

            return session;
        }
    }

    async refreshSession(session: Session) {
        if (this.callback.refreshSession !== undefined) {
            const newSession = await this.callback.refreshSession(session, this.maxAge);

            return newSession;
        } else {
            return session;
        }
    }

    async verifySession(session: Session) {
        if (this.callback.verifySession !== undefined) {
            const verified = await this.callback.verifySession(session);

            return verified;
        } else {
            return true;
        }
    }

    async invalidateSession(session: Session) {
        if (this.callback.invalidateSession !== undefined) {
            await this.callback.invalidateSession(session);
        }
    }

    async createSessionCookie(session: Session | undefined) {
        let setCookie: string;

        if (session === undefined) {
            setCookie = cookie.serialize('_monban_token', '', {
                ...this.cookieOptions,
                maxAge: 0,
            });
        } else {
            const token = this.encodeToken(session);
            setCookie = cookie.serialize('_monban_token', token, {
                ...this.cookieOptions,
                maxAge: this.maxAge,
            });
        }

        return setCookie;
    }

    async createUser(profile: InferProfile<T>) {
        if (this.callback.createUser !== undefined) {
            const userId = await this.callback.createUser(profile);

            return userId;
        } else {
            const userId = uuidv4();

            return userId;
        }
    }

    async verifyUser(profile: InferProfile<T>) {
        if (this.callback.verifyUser !== undefined) {
            const userId = await this.callback.verifyUser(profile);

            return userId;
        } else {
            return undefined;
        }
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

    async isAuthenticated(req: Request) {
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

            const session: Session = {
                id: payload.sessionId,
                userId: payload.sub,
            };

            if (await this.verifySession(session)) {
                return session;
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
