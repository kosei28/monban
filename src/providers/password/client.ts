import { ProviderClient, ProviderClientOptions } from '../../client';

export class PasswordClient extends ProviderClient {
    async signUp(options: ProviderClientOptions, email: string, password: string) {
        try {
            await fetch(`${options.endpoint}/providers/${options.provider}/signup`, {
                method: 'post',
                headers: {
                    'content-type': 'application/json',
                    'x-monban-csrf-token': options.csrfToken,
                },
                body: JSON.stringify({
                    email,
                    password,
                }),
            });

            return true;
        } catch (e) {
            return false;
        }
    }

    async signIn(options: ProviderClientOptions, email: string, password: string) {
        try {
            await fetch(`${options.endpoint}/providers/${options.provider}/signin`, {
                method: 'post',
                headers: {
                    'content-type': 'application/json',
                    'x-monban-csrf-token': options.csrfToken,
                },
                body: JSON.stringify({
                    email,
                    password,
                }),
            });

            return true;
        } catch (e) {
            return false;
        }
    }
}
