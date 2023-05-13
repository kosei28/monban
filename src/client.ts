import { InferSessionUser, InferUser, Monban, Session } from './main';

export abstract class ProviderClient {
    abstract signIn(endpoint: string): Promise<void>;
}

export type ProviderClients = { [key: string]: ProviderClient };

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type OnSessionChangeCallback<T extends Monban<any, any, any>> = (
    session: Session<InferSessionUser<T>> | undefined,
) => void;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export class MonbanClient<T extends Monban<any, any, any>, U extends ProviderClients> {
    protected endpoint: string;
    protected providerClients: U;
    protected onSessionChangeCallbacks: OnSessionChangeCallback<T>[] = [];

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

    constructor(endpoint: string, providerClients: U) {
        this.endpoint = endpoint;
        this.providerClients = providerClients;
    }

    onSessionChange(callback: OnSessionChangeCallback<T>) {
        this.triggerOnSessionChange(callback);
        this.onSessionChangeCallbacks.push(callback);
    }

    signIn = new Proxy(
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
                return async (...args: any[]) => {
                    // eslint-disable-next-line @typescript-eslint/no-explicit-any
                    await (providerClient.signIn as any)(this.endpoint, ...args);
                    await this.triggerOnSessionChange();
                };
            },
        },
    ) as { [key in keyof U]: U[key]['signIn'] };

    async signOut() {
        await fetch(`${this.endpoint}/signout`);
        await this.triggerOnSessionChange();
    }

    async getSession() {
        const res = await fetch(`${this.endpoint}/session`);
        const session = (await res.json()) as Session<InferSessionUser<T>>;

        return session;
    }

    async getUser() {
        const res = await fetch(`${this.endpoint}/user`);
        const user = (await res.json()) as InferUser<T>;

        return user;
    }

    async resetCsrfToken() {
        const res = await fetch(`${this.endpoint}/csrf`);
        const { token } = (await res.json()) as { token: string };

        localStorage.setItem('_monbanCsrfToken', token);

        return token;
    }

    async getCsrfToken() {
        const token = localStorage.getItem('_monbanCsrfToken');

        if (token !== null) {
            return token;
        } else {
            const token = await this.resetCsrfToken();

            return token;
        }
    }
}
