import { ProviderClient, ProviderClientOptions } from '../../client';
export declare class JsonClient<T> extends ProviderClient {
    signUp(options: ProviderClientOptions, body: T): Promise<boolean>;
    signIn(options: ProviderClientOptions, body: T): Promise<boolean>;
}
