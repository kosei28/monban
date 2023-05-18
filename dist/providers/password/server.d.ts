import { Monban, Provider, Providers } from '../../main';
export type PasswordProfile = {
    id: string;
    email: string;
    password: string;
    provider: 'password';
};
export declare class PasswordProvider extends Provider<PasswordProfile> {
    authenticate(req: Request, monban: Monban<any, Providers<PasswordProfile>>): Promise<{
        profile: PasswordProfile;
        userId: string | undefined;
    } | undefined>;
    handleRequest(req: Request, endpoint: string, monban: Monban<any, Providers<PasswordProfile>>): Promise<Response>;
}
