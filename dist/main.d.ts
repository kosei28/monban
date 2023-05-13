import * as cookie from 'cookie';
export type Session<T extends SessionUserBase> = {
    id?: string;
    user: T;
};
export type SessionUserBase = {
    id: string;
};
export type UserBase = {
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
export type Providers<T extends AccountInfoBase> = {
    [name: string]: Provider<T>;
};
export type InferAccountInfo<T> = T extends Providers<infer U> ? U : never;
export declare abstract class Provider<T extends AccountInfoBase> {
    abstract handleSignIn(req: Request, endpoint: string, monban: Monban<any, any, T>): Promise<Response>;
}
export type MonbanCallback<T extends SessionUserBase, U extends UserBase, V extends AccountInfoBase> = {
    createSession?: (user: U, accountInfo: V, maxAge: number) => Promise<Session<T>>;
    refreshSession?: (oldSession: Session<T>, maxAge: number) => Promise<Session<T>>;
    verifySession?: (session: Session<T>) => Promise<boolean>;
    deleteSession?: (session: Session<T>) => Promise<void>;
    createUser?: (accountInfo: V) => Promise<U>;
    getUser?: (userId: string) => Promise<U | undefined>;
    deleteUser?: (userId: string) => Promise<void>;
};
export type MonbanOptions<T extends SessionUserBase, U extends UserBase, V extends AccountInfoBase> = {
    secret: string;
    maxAge?: number;
    csrf?: boolean;
    cookie?: cookie.CookieSerializeOptions;
    callback?: MonbanCallback<T, U, V>;
};
export declare class Monban<T extends SessionUserBase, U extends UserBase, V extends AccountInfoBase> {
    protected providers: Providers<V>;
    protected secret: string;
    protected maxAge: number;
    protected csrf: boolean;
    protected cookieOptions: cookie.CookieSerializeOptions;
    protected callback: MonbanCallback<T, U, V>;
    constructor(providers: Providers<V>, options: MonbanOptions<T, U, V>);
    createSession(user: U, accountInfo: V): Promise<Session<T>>;
    refreshSession(oldSession: Session<T>): Promise<Session<T>>;
    verifySession(session: Session<T>): Promise<boolean>;
    deleteSession(session: Session<T>): Promise<void>;
    createUser(accountInfo: V): Promise<{
        id: string;
    }>;
    getUser(userId: string): Promise<U | undefined>;
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
