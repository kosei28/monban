import { Monban, Provider, Providers } from '../../main';
type PasswordAuthInfo = {
    id: string;
    email: string;
    password: string;
    provider: 'password';
};
export declare class PasswordProvider extends Provider<PasswordAuthInfo> {
    authenticate(req: Request, monban: Monban<any, Providers<PasswordAuthInfo>>): Promise<{
        authInfo: PasswordAuthInfo;
        userId: string | undefined;
    } | undefined>;
    handleRequest(req: Request, endpoint: string, monban: Monban<any, Providers<PasswordAuthInfo>>): Promise<Response>;
}
export {};
