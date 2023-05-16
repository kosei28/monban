import { ProviderClient, ProviderClientOptions } from '../../client';
export declare class PasswordClient extends ProviderClient {
    signUp(options: ProviderClientOptions, email: string, password: string): Promise<boolean>;
    signIn(options: ProviderClientOptions, email: string, password: string): Promise<boolean>;
}
