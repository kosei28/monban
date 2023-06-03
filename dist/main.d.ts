import * as cookie from 'cookie';
export type User = {
    id: string;
};
export type Session<T extends User> = {
    id: string;
    user: T;
};
export declare abstract class Adapter {
    abstract createSession(session: Session<User>, maxAge: number): Promise<void>;
    abstract verifySession(session: Session<User>): Promise<boolean>;
    abstract extendSession(session: Session<User>): Promise<void>;
    abstract invalidateSession(sessionId: string): Promise<void>;
    abstract invalidateUserSessions(userId: string): Promise<void>;
}
export type TokenPayload<T extends User> = {
    sub?: string;
    session: Session<T>;
    iat: number;
    exp: number;
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
export type MonbanCallbacks<T extends User, U extends Providers<any>> = {
    authenticate: (profile: InferProfile<U>) => Promise<T>;
};
export type MonbanOptions<T extends User, U extends Providers<any>> = {
    secret: string;
    maxAge?: number;
    csrf?: boolean;
    cookie?: cookie.CookieSerializeOptions;
    adapter?: Adapter;
    callbacks: MonbanCallbacks<T, U>;
};
export declare class Monban<T extends User, U extends Providers<any>> {
    protected providers: U;
    protected secret: string;
    protected maxAge: number;
    protected csrf: boolean;
    protected adapter?: Adapter;
    protected callbacks: MonbanCallbacks<T, U>;
    cookieOptions: cookie.CookieSerializeOptions;
    constructor(providers: U, options: MonbanOptions<T, U>);
    encodeToken(session: Session<T>): string;
    decodeToken(token: string): TokenPayload<T> | undefined;
    createSession(profile: InferProfile<U>): Promise<{
        id: string;
        user: T;
    }>;
    verifySession(session: Session<T>): Promise<boolean>;
    extendSession(session: Session<T>): Promise<void>;
    invalidateSession(sessionId: string): Promise<void>;
    invalidateUserSessions(userId: string): Promise<void>;
    createSessionCookie(session: Session<T> | undefined): string;
    createCsrfToken(): {
        token: string;
        setCookie: string;
    };
    isAuthenticated(req: Request): Promise<Session<T> | undefined>;
    handleRequest(req: Request, endpoint: string): Promise<Response>;
}
