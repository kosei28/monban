import * as cookie from 'cookie';
declare global {
    var monbanSession: {
        [K: string]: string;
    } | undefined;
}
export declare abstract class SessionStore {
    abstract create(userId: string): Promise<string>;
    abstract get(sessionId: string): Promise<string | undefined>;
    abstract delete(sessionId: string): Promise<void>;
}
export declare class MemorySessionStore extends SessionStore {
    create(userId: string): Promise<string>;
    get(sessionId: string): Promise<string | undefined>;
    delete(sessionId: string): Promise<void>;
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
export declare class Monban<T extends UserBase> {
    protected sessionStore: MemorySessionStore;
    protected secret: string;
    protected maxAge: number;
    protected csrf: boolean;
    protected cookieOptions: cookie.CookieSerializeOptions;
    constructor(sessionStore: MemorySessionStore, options: SessionManagerOptions);
    createToken(user: T): Promise<string>;
    decodeToken(token: string): Promise<TokenPayload<T> | undefined>;
    verify(payload: TokenPayloadInput<T>): Promise<Session<T> | undefined>;
    getSetCookie(user: T | undefined): Promise<string>;
    createCsrfToken(): Promise<{
        token: string;
        setCookie: string;
    }>;
    getSession(req: Request): Promise<Session<T> | undefined>;
}
export {};
