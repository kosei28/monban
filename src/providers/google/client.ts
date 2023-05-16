import { ProviderClient, ProviderClientOptions } from '../../client';

export class GoogleClient extends ProviderClient {
    async signIn(options: ProviderClientOptions) {
        location.href = `${options.endpoint}/providers/google/signin`;
    }
}
