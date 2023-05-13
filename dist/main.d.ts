import * as cookie from 'cookie';
export type Session<T extends SessionUserBase> = {
    id?: string;
    user: T;
};
export type SessionUserBase = {
    id: string;
};
export type TokenPayloadInput = {
    sub: string;
    sessionId?: string;
};
export type TokenPayload = TokenPayloadInput & {
    iat: number;
    exp: number;
};
export type AccountInfoBase = {
    provider: string;
};
export type Providers<T extends SessionUserBase, U extends AccountInfoBase> = {
    [name: string]: Provider<T, U>;
};
export type InferAccountInfo<T> = T extends Providers<SessionUserBase, infer U> ? U : never;
export declare abstract class Provider<T extends SessionUserBase, U extends AccountInfoBase> {
    abstract handleSignIn(req: Request, endpoint: string, monban: Monban<T, U>): Promise<Response>;
}
export type MonbanCallback<T extends SessionUserBase, U extends AccountInfoBase> = {
    createSession?: (accountInfo: U, userId: string, maxAge: number) => Promise<Session<T>>;
    refreshSession?: (oldSession: Session<T>, maxAge: number) => Promise<Session<T>>;
    verifySession?: (session: Session<T>) => Promise<boolean>;
    deleteSession?: (session: Session<T>) => Promise<void>;
    createUser?: (accountInfo: U) => Promise<string>;
    getUser?: (userId: string) => Promise<object | undefined>;
    deleteUser?: (userId: string) => Promise<void>;
};
export type MonbanOptions<T extends SessionUserBase, U extends AccountInfoBase> = {
    secret: string;
    maxAge?: number;
    csrf?: boolean;
    cookie?: cookie.CookieSerializeOptions;
    callback?: MonbanCallback<T, U>;
};
export declare class Monban<T extends SessionUserBase, U extends AccountInfoBase> {
    protected providers: Providers<T, U>;
    protected secret: string;
    protected maxAge: number;
    protected csrf: boolean;
    protected cookieOptions: cookie.CookieSerializeOptions;
    protected callback: MonbanCallback<T, U>;
    constructor(providers: Providers<T, U>, options: MonbanOptions<T, U>);
    createSession(accountInfo: U, userId: string): Promise<Session<T>>;
    refreshSession(oldSession: Session<T>): Promise<Session<T>>;
    verifySession(session: Session<T>): Promise<boolean>;
    deleteSession(session: Session<T>): Promise<void>;
    createUser(accountInfo: U): Promise<string>;
    getUser(userId: string): Promise<object | undefined>;
    deleteUser(userId: string): Promise<void>;
    createToken(session: Session<T>): Promise<string>;
    decodeToken(token: string): Promise<(TokenPayloadInput & {
        iat: number;
        exp: number;
    } & {
        user: T;
    }) | undefined>;
    verify(payload: TokenPayloadInput & {
        user: T;
    }): Promise<Session<T> | undefined>;
    getSetCookie(session: Session<T> | undefined): Promise<string>;
    createCsrfToken(): Promise<{
        token: string;
        setCookie: string;
    }>;
    getSession(req: Request): Promise<Session<T> | undefined>;
    handleRequest(req: Request, endpoint: string): Promise<Response>;
}
