import * as cookie from 'cookie';
import { Hono } from 'hono';
import * as jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';

export type User = {
    id: string;
};

export type Session<T extends User> = {
    id: string;
    user: T;
};

export abstract class Adapter {
    abstract createSession(session: Session<User>, maxAge: number): Promise<void>;
    abstract verifySession(sessionId: string): Promise<boolean>;
    abstract extendSession(sessionId: string, maxAge: number): Promise<void>;
    abstract invalidateSession(sessionId: string): Promise<void>;
    abstract invalidateUserSessions(userId: string): Promise<void>;
}

export type TokenPayload<T extends User> = {
    sub?: string;
    session: Session<T>;
    iat: number;
    exp: number;
};

export type Profile = {
    provider: string;
};

export abstract class Provider<T extends Profile> {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    abstract handleRequest(req: Request, endpoint: string, monban: Monban<any, Providers<T>>): Promise<Response>;
}

export type Providers<T extends Profile> = { [name: string]: Provider<T> };

export type InferProfile<T> = T extends Providers<infer U> ? U : never;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type MonbanCallbacks<T extends User, U extends Providers<any>> = {
    authenticate: (profile: InferProfile<U>) => Promise<T>;
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type MonbanOptions<T extends User, U extends Providers<any>> = {
    secret: string;
    maxAge?: number;
    csrf?: boolean;
    cookie?: cookie.CookieSerializeOptions;
    adapter?: Adapter;
    callbacks: MonbanCallbacks<T, U>;
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export class Monban<T extends User, U extends Providers<any>> {
    protected providers: U;
    protected secret: string;
    protected maxAge = 60 * 60;
    protected csrf = true;
    protected adapter?: Adapter;
    protected callbacks: MonbanCallbacks<T, U>;

    cookieOptions: cookie.CookieSerializeOptions = {
        path: '/',
        sameSite: 'lax',
        secure: true,
        httpOnly: true,
    };

    constructor(providers: U, options: MonbanOptions<T, U>) {
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

    encodeToken(session: Session<T>) {
        const token = jwt.sign(
            {
                sub: session.user.id,
                session: session,
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
            }) as TokenPayload<T>;

            return session;
        } catch (e) {
            return undefined;
        }
    }

    async createSession(profile: InferProfile<U>) {
        const user = await this.callbacks.authenticate(profile);
        const session = {
            id: uuidv4(),
            user,
        };

        if (this.adapter !== undefined) {
            await this.adapter.createSession(session, this.maxAge);
        }

        return session;
    }

    async verifySession(session: Session<T>) {
        if (this.adapter !== undefined) {
            const verified = await this.adapter.verifySession(session.id);

            return verified;
        } else {
            return true;
        }
    }

    async extendSession(session: Session<T>) {
        if (this.adapter !== undefined) {
            await this.adapter.extendSession(session.id, this.maxAge);
        }
    }

    async invalidateSession(sessionId: string) {
        if (this.adapter !== undefined) {
            await this.adapter.invalidateSession(sessionId);
        }
    }

    async invalidateUserSessions(userId: string) {
        if (this.adapter !== undefined) {
            await this.adapter.invalidateUserSessions(userId);
        }
    }

    createSessionCookie(session: Session<T> | undefined) {
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

    createCsrfToken() {
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
