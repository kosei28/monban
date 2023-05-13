import { Auth } from 'googleapis';
import { Monban, SessionUserBase, Provider } from '../../main';
type GoogleAccountInfo = {
    id: string;
    name: string;
    email: string;
    picture: string;
    tokens: Auth.Credentials;
    provider: 'google';
};
export declare class GoogleProvider<T extends SessionUserBase> extends Provider<T, GoogleAccountInfo> {
    protected clientId: string;
    protected clientSecret: string;
    constructor(option: {
        clientId: string;
        clientSecret: string;
    });
    getAuthUrl(callbackUrl: string): string;
    authenticate(req: Request, callbackUrl: string): Promise<GoogleAccountInfo | undefined>;
    handleSignIn(req: Request, endpoint: string, monban: Monban<T, GoogleAccountInfo>): Promise<Response>;
}
export {};
