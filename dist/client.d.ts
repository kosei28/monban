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
export type ProviderClients = {
    [key: string]: ProviderClient;
};
export type OnSessionChangeCallback<T extends Monban<any, any>> = (session: Session<InferSessionUser<T>> | undefined) => void;
export declare class MonbanClient<T extends Monban<any, any>, U extends ProviderClients> {
    protected endpoint: string;
    protected providerClients: U;
    protected onSessionChangeCallbacks: OnSessionChangeCallback<T>[];
    constructor(endpoint: string, providerClients: U);
    protected triggerOnSessionChange(callback?: OnSessionChangeCallback<T>): Promise<void>;
    onSessionChange(callback: OnSessionChangeCallback<T>): void;
    protected createProviderMethodProxy<V extends ProviderClientMethods>(method: V): { [key in keyof U]: U[key][V] extends (options: ProviderClientOptions, ...args: infer P) => infer R ? (...args: P) => R : never; };
    signUp: { [key in keyof U]: U[key]["signUp"] extends (options: ProviderClientOptions, ...args: infer P) => infer R ? (...args: P) => R : never; };
    signIn: { [key in keyof U]: U[key]["signIn"] extends (options: ProviderClientOptions, ...args: infer P) => infer R ? (...args: P) => R : never; };
    signOut(): Promise<void>;
    getSession(): Promise<Session<InferSessionUser<T>> | undefined>;
    getCsrfToken(): Promise<string>;
}
export {};
