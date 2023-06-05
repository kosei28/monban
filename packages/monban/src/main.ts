import * as cookie from 'cookie';
import * as jose from 'jose';
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

export type TokenPayload<T extends User> = jose.JWTPayload & {
    sub?: string;
    session: Session<T>;
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
    getUser: (profile: InferProfile<U>) => Promise<T> | undefined;
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

    async encodeToken(session: Session<T>) {
        const secret = new TextEncoder().encode(this.secret);
        const token = await new jose.SignJWT({ sub: session.user.id, session })
            .setProtectedHeader({ alg: 'HS256' })
            .setExpirationTime(`${this.maxAge}s`)
            .sign(secret);

        return token;
    }

    async decodeToken(token: string) {
        try {
            const secret = new TextEncoder().encode(this.secret);
            const decodedToken = await jose.jwtVerify(token, secret);
            const payload = decodedToken.payload as TokenPayload<T>;

            return payload;
        } catch (e) {
            return undefined;
        }
    }

    async createSession(profile: InferProfile<U>) {
        const user = await this.callbacks.getUser(profile);

        if (user === undefined) {
            return undefined;
        }

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

    async createSessionCookie(session: Session<T> | undefined) {
        let setCookie: string;

        if (session === undefined) {
            setCookie = cookie.serialize('_monban_token', '', {
                ...this.cookieOptions,
                maxAge: 0,
            });
        } else {
            const token = await this.encodeToken(session);
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

    async handleRequest(req: Request, endpoint: string) {
        const url = new URL(req.url);

        if (!url.pathname.startsWith(endpoint)) {
            return new Response(undefined, {
                status: 404,
            });
        }

        const pathnames = url.pathname
            .slice(endpoint.length)
            .split('/')
            .filter((pathname) => pathname !== '');

        if (pathnames[0] === 'providers') {
            const providerName = pathnames[1];
            const provider = this.providers[providerName];

            if (provider === undefined) {
                return new Response(undefined, {
                    status: 404,
                });
            }

            const res = provider.handleRequest(req, `${endpoint}/providers/${providerName}`, this);

            return res;
        } else if (pathnames[0] === 'signout' && req.method === 'GET') {
            const session = await this.isAuthenticated(req);

            if (session !== undefined) {
                await this.invalidateSession(session.id);
            }

            const setCookie = await this.createSessionCookie(undefined);

            return new Response(undefined, {
                headers: {
                    'set-cookie': setCookie,
                },
            });
        } else if (pathnames[0] === 'session' && req.method === 'GET') {
            const session = await this.isAuthenticated(req);

            if (session === undefined) {
                return new Response(undefined, {
                    status: 401,
                });
            }

            await this.extendSession(session);
            const setCookie = await this.createSessionCookie(session);
            return new Response(JSON.stringify(session), {
                headers: {
                    'set-cookie': setCookie,
                },
            });
        } else if (pathnames[0] === 'csrf' && req.method === 'GET') {
            const { token, setCookie } = this.createCsrfToken();

            return new Response(JSON.stringify({ token }), {
                headers: {
                    'set-cookie': setCookie,
                },
            });
        } else {
            return new Response(undefined, {
                status: 404,
            });
        }
    }
}
