import { Auth } from 'googleapis';
import { Monban, Provider } from '../../main';
type GoogleAuthInfo = {
    id: string;
    name: string;
    email: string;
    picture: string;
    tokens: Auth.Credentials;
    provider: 'google';
};
export declare class GoogleProvider extends Provider<GoogleAuthInfo> {
    protected clientId: string;
    protected clientSecret: string;
    constructor(option: {
        clientId: string;
        clientSecret: string;
    });
    getAuthUrl(callbackUrl: string): string;
    authenticate(req: Request, callbackUrl: string, monban: Monban<any, GoogleAuthInfo>): Promise<{
        authInfo: GoogleAuthInfo;
        userId: string | undefined;
    } | undefined>;
    handleRequest(req: Request, endpoint: string, monban: Monban<any, GoogleAuthInfo>): Promise<Response>;
}
export {};
