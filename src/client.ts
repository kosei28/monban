import * as cookie from 'cookie';
import { InferSessionUser, Monban, Session } from './main';

export type ProviderClientOptions = {
    endpoint: string;
    csrfToken: string;
};

export abstract class ProviderClient {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    signUp?(options: ProviderClientOptions, ...args: any): Promise<any>;

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    abstract signIn(options: ProviderClientOptions, ...args: any): Promise<any>;
}

type RemoveUndefined<T> = T extends undefined ? never : T;

export type ProviderClientMethods = RemoveUndefined<
    {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        [K in keyof ProviderClient]: ProviderClient[K] extends ((...args: any) => any) | undefined ? K : never;
    }[keyof ProviderClient]
>;

export type ProviderClients<T extends ProviderClient> = { [key: string]: T };

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type OnSessionChangeCallback<T extends Monban<any, any>> = (
    session: Session<InferSessionUser<T>> | undefined,
) => void;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export class MonbanClient<T extends Monban<any, any>, U extends ProviderClients<any>> {
    protected endpoint: string;
    protected providerClients: U;
    protected onSessionChangeCallbacks: OnSessionChangeCallback<T>[] = [];

    constructor(endpoint: string, providerClients: U) {
        this.endpoint = endpoint;
        this.providerClients = providerClients;
    }

    protected async triggerOnSessionChange(callback?: OnSessionChangeCallback<T>) {
        const session = await this.getSession();

        if (callback !== undefined) {
            callback(session);
        } else {
            this.onSessionChangeCallbacks.forEach((callback) => {
                callback(session);
            });
        }
    }

    onSessionChange(callback: OnSessionChangeCallback<T>) {
        this.triggerOnSessionChange(callback);
        this.onSessionChangeCallbacks.push(callback);
    }

    protected createProviderMethodProxy<V extends ProviderClientMethods>(method: V) {
        const proxy = new Proxy(
            {},
            {
                get: (target, provider) => {
                    if (typeof provider !== 'string') {
                        return undefined;
                    }

                    const providerClient = this.providerClients[provider];

                    if (providerClient === undefined) {
                        return undefined;
                    }

                    // eslint-disable-next-line @typescript-eslint/no-explicit-any
                    return async (...args: any) => {
                        // eslint-disable-next-line @typescript-eslint/no-explicit-any
                        const result = await (providerClient[method] as any)(
                            {
                                endpoint: this.endpoint,
                                csrfToken: await this.getCsrfToken(),
                            },
                            ...args,
                        );

                        this.triggerOnSessionChange();

                        return result;
                    };
                },
            },
        ) as {
            [K in keyof U]: U[K][V] extends (options: ProviderClientOptions, ...args: infer P) => infer R
                ? (...args: P) => R
                : never;
        };

        return proxy;
    }

    signUp = this.createProviderMethodProxy('signUp');

    signIn = this.createProviderMethodProxy('signIn');

    async signOut() {
        await fetch(`${this.endpoint}/signout`);
        await this.triggerOnSessionChange();
    }

    async getSession() {
        const res = await fetch(`${this.endpoint}/session`);

        try {
            const session = (await res.json()) as Session<InferSessionUser<T>>;

            return session;
        } catch (e) {
            return undefined;
        }
    }

    async getCsrfToken() {
        const { _monban_csrf_token: token } = cookie.parse(document.cookie);

        if (token !== undefined) {
            return token;
        } else {
            const res = await fetch(`${this.endpoint}/csrf`);
            const { token } = (await res.json()) as { token: string };

            return token;
        }
    }
}
