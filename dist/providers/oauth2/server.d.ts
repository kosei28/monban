import { Monban, Provider, type Profile, type Providers } from '../../main';
export type OAuth2Tokens = {
    access_token?: string;
    refresh_token?: string;
};
export declare class OAuth2Provider<T extends Profile, U extends OAuth2Tokens> extends Provider<T> {
    protected authorizationUrl: string;
    protected tokenUrl: string;
    protected scope?: string;
    protected clientId: string;
    protected clientSecret: string;
    protected getProfile: (tokens: U) => Promise<T | undefined>;
    constructor(options: {
        authorizationUrl: string;
        tokenUrl: string;
        scope?: string;
        clientId: string;
        clientSecret: string;
        getProfile: (tokens: U) => Promise<T | undefined>;
    });
    getAuthUrl(callbackUrl: string, redirectUrl: string, stateId: string): string;
    authenticate(req: Request, callbackUrl: string): Promise<T | undefined>;
    handleRequest(req: Request, endpoint: string, monban: Monban<any, Providers<T>>): Promise<Response>;
}
