import { ProviderClient, ProviderClientOptions } from '../../client';

export class JsonClient<T> extends ProviderClient {
    async signIn(options: ProviderClientOptions, body: T) {
        try {
            await fetch(`${options.endpoint}/providers/${options.provider}/signin`, {
                method: 'post',
                headers: {
                    'content-type': 'application/json',
                    'x-monban-csrf-token': options.csrfToken,
                },
                body: JSON.stringify(body),
            });

            return true;
        } catch (e) {
            return false;
        }
    }
}
