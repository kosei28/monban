import { ProviderClient, type ProviderClientOptions } from '../../client';

export class OAuth2Client extends ProviderClient {
    async signIn(options: ProviderClientOptions, redirectUrl?: string) {
        let url = `${options.endpoint}/providers/${options.provider}/signin?location=${location.href}`;

        if (redirectUrl !== undefined) {
            url += `&redirect=${redirectUrl}`;
        }

        location.href = url;
    }
}
