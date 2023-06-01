import { ProviderClient, ProviderClientOptions } from '../../client';
export declare class JsonClient<T> extends ProviderClient {
    signIn(options: ProviderClientOptions, body: T): Promise<boolean>;
}
