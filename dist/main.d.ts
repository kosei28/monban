import * as cookie from 'cookie';
export type SessionUser = {
    id: string;
};
export type Session<T extends SessionUser> = {
    id?: string;
    user: T;
};
export type InferSessionUser<T> = T extends Monban<infer U, any> ? U : never;
export type AuthInfo = {
    provider: string;
};
export declare abstract class Provider<T extends AuthInfo> {
    abstract handleRequest(req: Request, endpoint: string, monban: Monban<any, T>): Promise<Response>;
}
export type Providers<T extends AuthInfo> = {
    [name: string]: Provider<T>;
};
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
export type MonbanCallback<T extends SessionUser, U extends AuthInfo> = {
    createSession?: (userId: string, authInfo: U, maxAge: number) => Promise<Session<T>>;
    refreshSession?: (oldSession: Session<T>, maxAge: number) => Promise<Session<T>>;
    verifySession?: (session: Session<T>) => Promise<boolean>;
    deleteSession?: (session: Session<T>) => Promise<void>;
    createAccount?: (authInfo: U) => Promise<string>;
    verifyUser?: (authInfo: U) => Promise<string | undefined>;
};
export type MonbanOptions<T extends SessionUser, U extends AuthInfo> = {
    secret: string;
    maxAge?: number;
    csrf?: boolean;
    cookie?: cookie.CookieSerializeOptions;
    callback?: MonbanCallback<T, U>;
};
export declare class Monban<T extends SessionUser, U extends AuthInfo> {
    protected providers: Providers<U>;
    protected secret: string;
    protected maxAge: number;
    protected csrf: boolean;
    protected cookieOptions: cookie.CookieSerializeOptions;
    protected callback: MonbanCallback<T, U>;
    constructor(providers: Providers<U>, options: MonbanOptions<T, U>);
    createSession(userId: string, authInfo: U): Promise<Session<T>>;
    refreshSession(oldSession: Session<T>): Promise<Session<T>>;
    verifySession(session: Session<T>): Promise<boolean>;
    deleteSession(session: Session<T>): Promise<void>;
    createAccount(authInfo: U): Promise<string>;
    verifyUser(authInfo: U): Promise<string | undefined>;
    createToken(session: Session<T>): Promise<string>;
    decodeToken(token: string): Promise<TokenPayload<T> | undefined>;
    verify(payload: TokenPayloadInput<T>): Promise<Session<T> | undefined>;
    getSetCookie(session: Session<T> | undefined): Promise<string>;
    createCsrfToken(): Promise<{
        token: string;
        setCookie: string;
    }>;
    getSession(req: Request): Promise<Session<T> | undefined>;
    handleRequest(req: Request, endpoint: string): Promise<Response>;
}
