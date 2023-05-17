import * as cookie from 'cookie';
export type SessionUser = {
    id: string;
};
export type InferSessionUser<T> = T extends Monban<infer U, any> ? U : never;
export type AuthInfo = {
    provider: string;
};
export declare abstract class Provider<T extends AuthInfo> {
    abstract handleRequest(req: Request, endpoint: string, monban: Monban<any, Providers<T>>): Promise<Response>;
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
export type MonbanCallback<T extends SessionUser, U extends Providers<any>> = {
    createToken?: (userId: string, authInfo: InferAuthInfo<U>, maxAge: number) => Promise<TokenPayloadInput<T>>;
    refreshToken?: (oldPayload: TokenPayload<T>, maxAge: number) => Promise<TokenPayloadInput<T>>;
    verifyToken?: (payload: TokenPayload<T>) => Promise<boolean>;
    invalidateToken?: (payload: TokenPayload<T>) => Promise<void>;
    createAccount?: (authInfo: InferAuthInfo<U>) => Promise<string>;
    verifyUser?: (authInfo: InferAuthInfo<U>) => Promise<string | undefined>;
};
export type MonbanOptions<T extends SessionUser, U extends Providers<any>> = {
    secret: string;
    maxAge?: number;
    csrf?: boolean;
    cookie?: cookie.CookieSerializeOptions;
    callback?: MonbanCallback<T, U>;
};
export declare class Monban<T extends SessionUser, U extends Providers<any>> {
    protected providers: U;
    protected secret: string;
    protected maxAge: number;
    protected csrf: boolean;
    protected cookieOptions: cookie.CookieSerializeOptions;
    protected callback: MonbanCallback<T, U>;
    constructor(providers: U, options: MonbanOptions<T, U>);
    encodeToken(payload: TokenPayloadInput<T>): string;
    decodeToken(token: string): TokenPayload<T> | undefined;
    createToken(userId: string, authInfo: InferAuthInfo<U>): Promise<TokenPayloadInput<T>>;
    refreshToken(oldPayload: TokenPayload<T>): Promise<TokenPayloadInput<T>>;
    verifyToken(payload: TokenPayload<T>): Promise<boolean>;
    invalidateToken(payload: TokenPayload<T>): Promise<void>;
    createAccount(authInfo: InferAuthInfo<U>): Promise<string>;
    verifyUser(authInfo: InferAuthInfo<U>): Promise<string | undefined>;
    getTokenSetCookie(token: string | undefined): Promise<string>;
    createCsrfToken(): Promise<{
        token: string;
        setCookie: string;
    }>;
    getSession(req: Request): Promise<TokenPayload<T> | undefined>;
    handleRequest(req: Request, endpoint: string): Promise<Response>;
}
