import { ProviderClient, type ProviderClientOptions } from '../../client';
export declare class OAuth2Client extends ProviderClient {
    signIn(options: ProviderClientOptions, redirectUrl?: string): Promise<void>;
}
