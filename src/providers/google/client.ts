import { ProviderClient } from '../../client';

export class GoogleClient extends ProviderClient {
    async signIn(endpoint: string) {
        location.href = `${endpoint}/signin/google`;
    }
}
