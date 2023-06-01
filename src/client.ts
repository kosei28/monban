import * as cookie from 'cookie';
import type { Session } from './main';
import type { KeyOfSpecificTypeValue, OmitBySpecificTypeValue } from './types';

export type ProviderClientOptions = {
    endpoint: string;
    csrfToken: string;
    provider: string;
};

export abstract class ProviderClient {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    signUp?(options: ProviderClientOptions, ...args: any): Promise<any>;

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    abstract signIn(options: ProviderClientOptions, ...args: any): Promise<any>;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type ProviderClientMethods = KeyOfSpecificTypeValue<ProviderClient, ((...args: any) => any) | undefined>;

export type ProviderClients = { [key: string]: ProviderClient };

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type OnSessionChangeCallback = (session: Session | undefined) => void;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export class MonbanClient<T extends ProviderClients> {
    protected endpoint: string;
    protected providerClients: T;
    protected onSessionChangeCallbacks: OnSessionChangeCallback[] = [];

    constructor(endpoint: string, providerClients: T) {
        this.endpoint = endpoint;
        this.providerClients = providerClients;
    }

    protected async triggerOnSessionChange(callback?: OnSessionChangeCallback) {
        const session = await this.getSession();

        if (callback !== undefined) {
            callback(session);
        } else {
            this.onSessionChangeCallbacks.forEach((callback) => {
                callback(session);
            });
        }
    }

    async onSessionChange(callback: OnSessionChangeCallback) {
        this.onSessionChangeCallbacks.push(callback);
        await this.triggerOnSessionChange(callback);
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
                                provider,
                            } as ProviderClientOptions,
                            ...args,
                        );

                        await this.triggerOnSessionChange();

                        return result;
                    };
                },
            },
        ) as OmitBySpecificTypeValue<
            {
                [K in keyof T]: T[K][V] extends (options: ProviderClientOptions, ...args: infer P) => infer R
                    ? (...args: P) => R
                    : undefined;
            },
            undefined
        >;

        return proxy;
    }

    signUp = this.createProviderMethodProxy('signUp');

    signIn = this.createProviderMethodProxy('signIn');

    async signOut() {
        await fetch(`${this.endpoint}/signout`);
        await this.triggerOnSessionChange();
    }

    async getSession() {
        try {
            const res = await fetch(`${this.endpoint}/session`);
            const session = (await res.json()) as Session;

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
