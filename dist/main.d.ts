import * as cookie from 'cookie';
export type User = {
    id: string;
};
export type Profile = {
    provider: string;
};
export declare abstract class Provider<T extends Profile> {
    abstract handleRequest(req: Request, endpoint: string, monban: Monban<any, Providers<T>>): Promise<Response>;
}
export type Providers<T extends Profile> = {
    [name: string]: Provider<T>;
};
export type InferProfile<T> = T extends Providers<infer U> ? U : never;
export type Session<T extends User> = {
    id: string;
    user: T;
};
export type TokenPayload<T extends User> = {
    sub?: string;
    session: Session<T>;
    iat: number;
    exp: number;
};
export type MonbanCallback<T extends User, U extends Providers<any>> = {
    createSession: (profile: InferProfile<U>, maxAge: number) => Promise<Session<T>>;
    refreshSession?: (session: Session<T>, maxAge: number) => Promise<Session<T>>;
    verifySession?: (session: Session<T>) => Promise<boolean>;
    invalidateSession?: (session: Session<T>) => Promise<void>;
};
export type MonbanOptions<T extends User, U extends Providers<any>> = {
    secret: string;
    maxAge?: number;
    csrf?: boolean;
    cookie?: cookie.CookieSerializeOptions;
    callback: MonbanCallback<T, U>;
};
export declare class Monban<T extends User, U extends Providers<any>> {
    protected providers: U;
    protected secret: string;
    protected maxAge: number;
    protected csrf: boolean;
    protected callback: MonbanCallback<T, U>;
    cookieOptions: cookie.CookieSerializeOptions;
    constructor(providers: U, options: MonbanOptions<T, U>);
    encodeToken(session: Session<T>): string;
    decodeToken(token: string): TokenPayload<T> | undefined;
    createSession(profile: InferProfile<U>): Promise<Session<T>>;
    refreshSession(session: Session<T>): Promise<Session<T>>;
    verifySession(session: Session<T>): Promise<boolean>;
    invalidateSession(session: Session<T>): Promise<void>;
    createSessionCookie(session: Session<T> | undefined): Promise<string>;
    createCsrfToken(): Promise<{
        token: string;
        setCookie: string;
    }>;
    isAuthenticated(req: Request): Promise<Session<T> | undefined>;
    handleRequest(req: Request, endpoint: string): Promise<Response>;
}
