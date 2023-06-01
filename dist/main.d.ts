import * as cookie from 'cookie';
export type Profile = {
    provider: string;
};
export declare abstract class Provider<T extends Profile> {
    abstract handleRequest(req: Request, endpoint: string, monban: Monban<Providers<T>>): Promise<Response>;
}
export type Providers<T extends Profile> = {
    [name: string]: Provider<T>;
};
export type InferProfile<T> = T extends Providers<infer U> ? U : never;
export type Session = {
    id: string;
    userId: string;
};
export type TokenPayload = {
    sub: string;
    sessionId: string;
    iat: number;
    exp: number;
};
export type MonbanCallback<T extends Providers<any>> = {
    createSession?: (userId: string, maxAge: number) => Promise<Session>;
    refreshSession?: (session: Session, maxAge: number) => Promise<Session>;
    verifySession?: (session: Session) => Promise<boolean>;
    invalidateSession?: (session: Session) => Promise<void>;
    createUser?: (profile: InferProfile<T>) => Promise<string>;
    verifyUser?: (profile: InferProfile<T>) => Promise<string | undefined>;
};
export type MonbanOptions<T extends Providers<any>> = {
    secret: string;
    maxAge?: number;
    csrf?: boolean;
    cookie?: cookie.CookieSerializeOptions;
    callback?: MonbanCallback<T>;
};
export declare class Monban<T extends Providers<any>> {
    protected providers: T;
    protected secret: string;
    protected maxAge: number;
    protected csrf: boolean;
    protected callback: MonbanCallback<T>;
    cookieOptions: cookie.CookieSerializeOptions;
    constructor(providers: T, options: MonbanOptions<T>);
    encodeToken(session: Session): string;
    decodeToken(token: string): TokenPayload | undefined;
    createSession(userId: string): Promise<Session>;
    refreshSession(session: Session): Promise<Session>;
    verifySession(session: Session): Promise<boolean>;
    invalidateSession(session: Session): Promise<void>;
    createSessionCookie(session: Session | undefined): Promise<string>;
    createUser(profile: InferProfile<T>): Promise<string>;
    verifyUser(profile: InferProfile<T>): Promise<string | undefined>;
    createCsrfToken(): Promise<{
        token: string;
        setCookie: string;
    }>;
    isAuthenticated(req: Request): Promise<Session | undefined>;
    handleRequest(req: Request, endpoint: string): Promise<Response>;
}
