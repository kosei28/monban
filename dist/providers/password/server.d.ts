import { Monban, Provider, Providers } from '../../main';
export type PasswordProfile = {
    provider: 'password';
    id: string;
    email: string;
    password: string;
};
export declare class PasswordProvider extends Provider<PasswordProfile> {
    authenticate(req: Request, monban: Monban<any, Providers<PasswordProfile>>): Promise<{
        profile: PasswordProfile;
        userId: string | undefined;
    } | undefined>;
    handleRequest(req: Request, endpoint: string, monban: Monban<any, Providers<PasswordProfile>>): Promise<Response>;
}
