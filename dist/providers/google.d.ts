import { Auth } from 'googleapis';
import { Monban } from '../main';
import { Provider } from '.';
type GoogleAccountInfo = {
    id: string;
    name: string;
    email: string;
    picture: string;
    provider: 'google';
};
export declare class GoogleProvider extends Provider<GoogleAccountInfo> {
    protected clientId: string;
    protected clientSecret: string;
    protected callbackUrl: string;
    protected client: Auth.OAuth2Client;
    constructor(option: {
        clientId: string;
        clientSecret: string;
        callbackUrl: string;
    });
    getAuthUrl(): string;
    authenticate(req: Request): Promise<GoogleAccountInfo | undefined>;
    handleLogin(req: Request, endpoint: string, monban: Monban<GoogleAccountInfo>): Promise<Response>;
}
export {};
