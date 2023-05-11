import { v4 as uuidv4 } from 'uuid';
import * as jwt from 'jsonwebtoken';
import * as cookie from 'cookie';

declare global {
    // eslint-disable-next-line no-var
    var monbanSession: { [K: string]: string } | undefined;
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

type SessionManagerOptions = {
    secret: string;
    maxAge?: number;
    csrf?: boolean;
    cookie?: cookie.CookieSerializeOptions;
};

type UserBase = {
    id: string;
};

type Session<T extends UserBase> = {
    id: string;
    user: T;
};

type TokenPayloadInput<T extends UserBase> = {
    sub: string;
    sessionId: string;
    user: T;
};

type TokenPayload<T extends UserBase> = TokenPayloadInput<T> & {
    iat: number;
    exp: number;
};

export class Monban<T extends UserBase> {
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

    constructor(sessionStore: MemorySessionStore, options: SessionManagerOptions) {
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

    async createToken(user: T) {
        const sessionId = await this.sessionStore.create(user.id);
        const payload: TokenPayloadInput<T> = {
            sub: user.id,
            sessionId: sessionId,
            user,
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
        const userId = await this.sessionStore.get(payload.sessionId);

        if (userId !== undefined && userId === payload.sub) {
            const session: Session<T> = {
                id: payload.sessionId,
                user: payload.user,
            };

            return session;
        }

        return undefined;
    }

    async getSetCookie(user: T | undefined) {
        let setCookie: string;

        if (user === undefined) {
            setCookie = cookie.serialize('_monban_token', '', {
                ...this.cookieOptions,
                maxAge: 0,
            });
        } else {
            const token = await this.createToken(user);
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
}
