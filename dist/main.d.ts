import * as cookie from 'cookie';
declare global {
    var monbanSession: {
        [id: string]: string;
    } | undefined;
}
export type AccountInfoBase = {
    name: string;
    email: string;
    provider: string;
};
export type Providers<T extends AccountInfoBase> = {
    [name: string]: Provider<T>;
};
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
export declare abstract class Provider<T extends AccountInfoBase> {
    abstract handleLogin(req: Request, endpoint: string, monban: Monban<T>): Promise<Response>;
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
export declare abstract class Monban<T extends AccountInfoBase> {
    protected providers: Providers<T>;
    protected sessionStore: MemorySessionStore;
    protected secret: string;
    protected maxAge: number;
    protected csrf: boolean;
    protected cookieOptions: cookie.CookieSerializeOptions;
    constructor(providers: Providers<T>, sessionStore: MemorySessionStore, options: SessionManagerOptions);
    abstract createUser(accountInfo: T): Promise<string>;
    abstract getUser(userId: string): Promise<object>;
    abstract deleteUser(userId: string): Promise<void>;
    createToken(userId: string): Promise<string>;
    decodeToken(token: string): Promise<TokenPayload | undefined>;
    verify(payload: TokenPayloadInput): Promise<Session | undefined>;
    getSetCookie(userId: string | undefined): Promise<string>;
    createCsrfToken(): Promise<{
        token: string;
        setCookie: string;
    }>;
    getSession(req: Request): Promise<Session | undefined>;
    handleRequest(req: Request, endpoint: string): Promise<Response>;
}
