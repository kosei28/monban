import * as cookie from 'cookie';
import { AccountInfoBase, Providers } from './providers';
import { MemorySessionStore } from './session';
import { UserManager } from './user';
export * from './session';
export * from './user';
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
export type MonbanOptions = {
    secret: string;
    maxAge?: number;
    csrf?: boolean;
    cookie?: cookie.CookieSerializeOptions;
};
export declare abstract class Monban<T extends AccountInfoBase> {
    protected providers: Providers<T>;
    protected sessionStore: MemorySessionStore;
    protected userManager: UserManager<T>;
    protected secret: string;
    protected maxAge: number;
    protected csrf: boolean;
    protected cookieOptions: cookie.CookieSerializeOptions;
    constructor(providers: Providers<T>, sessionStore: MemorySessionStore, userManager: UserManager<T>, options: MonbanOptions);
    createUser(accountInfo: T): Promise<string>;
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
