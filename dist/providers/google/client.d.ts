import { ProviderClient, ProviderClientOptions } from '../../client';
export declare class GoogleClient extends ProviderClient {
    signIn(options: ProviderClientOptions, redirectUrl?: string): Promise<void>;
}
