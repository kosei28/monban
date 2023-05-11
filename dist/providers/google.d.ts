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
    constructor(option: {
        clientId: string;
        clientSecret: string;
    });
    getAuthUrl(callbackUrl: string): string;
    authenticate(req: Request, callbackUrl: string): Promise<GoogleAccountInfo | undefined>;
    handleLogin(req: Request, endpoint: string, monban: Monban<GoogleAccountInfo>): Promise<Response>;
}
export {};
