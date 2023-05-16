import { InferSessionUser, Monban, Session } from './main';
export type ProviderClientOptions = {
    endpoint: string;
    csrfToken: string;
};
export declare abstract class ProviderClient {
    signUp?(options: ProviderClientOptions, ...args: any): Promise<any>;
    abstract signIn(options: ProviderClientOptions, ...args: any): Promise<any>;
}
type RemoveUndefined<T> = T extends undefined ? never : T;
export type ProviderClientMethods = RemoveUndefined<{
    [K in keyof ProviderClient]: ProviderClient[K] extends ((...args: any) => any) | undefined ? K : never;
}[keyof ProviderClient]>;
export type ProviderClients<T extends ProviderClient> = {
    [key: string]: T;
};
export type InferProviderClient<T> = T extends ProviderClients<infer U> ? U : never;
export type OnSessionChangeCallback<T extends Monban<any, any>> = (session: Session<InferSessionUser<T>> | undefined) => void;
export declare class MonbanClient<T extends Monban<any, any>, U extends ProviderClient> {
    protected endpoint: string;
    protected providerClients: ProviderClients<U>;
    protected onSessionChangeCallbacks: OnSessionChangeCallback<T>[];
    constructor(endpoint: string, providerClients: ProviderClients<U>);
    protected triggerOnSessionChange(callback?: OnSessionChangeCallback<T>): Promise<void>;
    onSessionChange(callback: OnSessionChangeCallback<T>): void;
    protected createProviderMethodProxy<V extends ProviderClientMethods>(method: V): {
        [x: string]: U[V] extends (options: ProviderClientOptions, ...args: infer P) => infer R ? (...args: P) => R : never;
    };
    signUp: {
        [x: string]: U["signUp"] extends (options: ProviderClientOptions, ...args: infer P) => infer R ? (...args: P) => R : never;
    };
    signIn: {
        [x: string]: U["signIn"] extends (options: ProviderClientOptions, ...args: infer P) => infer R ? (...args: P) => R : never;
    };
    signOut(): Promise<void>;
    getSession(): Promise<Session<InferSessionUser<T>> | undefined>;
    getCsrfToken(): Promise<string>;
}
export {};
