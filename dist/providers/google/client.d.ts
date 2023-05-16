import { ProviderClient, ProviderClientOptions } from '../../client';
export declare class GoogleClient extends ProviderClient {
    signIn(options: ProviderClientOptions): Promise<void>;
}
