import * as cookie from 'cookie';
import { AccountInfoBase, Providers } from './providers';
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
type MonbanCallback<T extends AccountInfoBase, U extends SessionUserBase> = {
    createSession?: (accountInfo: T, userId: string, maxAge: number) => Promise<Session<U>>;
    refreshSession?: (oldSession: Session<U>, maxAge: number) => Promise<Session<U>>;
    verifySession?: (session: Session<U>) => Promise<boolean>;
    deleteSession?: (session: Session<U>) => Promise<void>;
    createUser?: (accountInfo: T) => Promise<string>;
    getUser?: (userId: string) => Promise<object | undefined>;
    deleteUser?: (userId: string) => Promise<void>;
};
export type MonbanOptions<T extends AccountInfoBase, U extends SessionUserBase> = {
    secret: string;
    maxAge?: number;
    csrf?: boolean;
    cookie?: cookie.CookieSerializeOptions;
    callback?: MonbanCallback<T, U>;
};
export declare class Monban<T extends AccountInfoBase, U extends SessionUserBase = SessionUserBase> {
    protected providers: Providers<T, U>;
    protected secret: string;
    protected maxAge: number;
    protected csrf: boolean;
    protected cookieOptions: cookie.CookieSerializeOptions;
    protected callback: MonbanCallback<T, U>;
    constructor(providers: Providers<T, U>, options: MonbanOptions<T, U>);
    createSession(accountInfo: T, userId: string): Promise<Session<U>>;
    refreshSession(oldSession: Session<U>): Promise<Session<U>>;
    verifySession(session: Session<U>): Promise<boolean>;
    deleteSession(session: Session<U>): Promise<void>;
    createUser(accountInfo: T): Promise<string>;
    getUser(userId: string): Promise<object | undefined>;
    deleteUser(userId: string): Promise<void>;
    createToken(session: Session<U>): Promise<string>;
    decodeToken(token: string): Promise<(TokenPayloadInput & {
        iat: number;
        exp: number;
    } & {
        user: U;
    }) | undefined>;
    verify(payload: TokenPayloadInput & {
        user: U;
    }): Promise<Session<U> | undefined>;
    getSetCookie(session: Session<U> | undefined): Promise<string>;
    createCsrfToken(): Promise<{
        token: string;
        setCookie: string;
    }>;
    getSession(req: Request): Promise<Session<U> | undefined>;
    handleRequest(req: Request, endpoint: string): Promise<Response>;
}
export {};
