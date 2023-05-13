import { ProviderClient } from '../../client';
export declare class GoogleClient extends ProviderClient {
    signIn(endpoint: string): Promise<void>;
}
