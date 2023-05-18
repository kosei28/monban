import { ProviderClient, ProviderClientOptions } from '../../client';

export class GoogleClient extends ProviderClient {
    async signIn(options: ProviderClientOptions, redirectUrl?: string) {
        let url = `${options.endpoint}/providers/google/signin`;

        if (redirectUrl !== undefined) {
            url += `?redirect=${redirectUrl}`;
        }

        location.href = url;
    }
}
