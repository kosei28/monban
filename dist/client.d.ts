import { InferSessionUser, Monban, TokenPayloadInput } from './main';
import { KeyOfSpecificTypeValue, OmitBySpecificTypeValue } from './types';
export type ProviderClientOptions = {
    endpoint: string;
    csrfToken: string;
    provider: string;
};
export declare abstract class ProviderClient {
    signUp?(options: ProviderClientOptions, ...args: any): Promise<any>;
    abstract signIn(options: ProviderClientOptions, ...args: any): Promise<any>;
}
export type ProviderClientMethods = KeyOfSpecificTypeValue<ProviderClient, ((...args: any) => any) | undefined>;
export type ProviderClients = {
    [key: string]: ProviderClient;
};
export type OnSessionChangeCallback<T extends Monban<any, any>> = (session: TokenPayloadInput<InferSessionUser<T>> | undefined) => void;
export declare class MonbanClient<T extends Monban<any, any>, U extends ProviderClients> {
    protected endpoint: string;
    protected providerClients: U;
    protected onSessionChangeCallbacks: OnSessionChangeCallback<T>[];
    constructor(endpoint: string, providerClients: U);
    protected triggerOnSessionChange(callback?: OnSessionChangeCallback<T>): Promise<void>;
    onSessionChange(callback: OnSessionChangeCallback<T>): void;
    protected createProviderMethodProxy<V extends ProviderClientMethods>(method: V): OmitBySpecificTypeValue<{ [K in keyof U]: U[K][V] extends (options: ProviderClientOptions, ...args: infer P) => infer R ? (...args: P) => R : undefined; }, undefined>;
    signUp: OmitBySpecificTypeValue<{ [K in keyof U]: U[K]["signUp"] extends (options: ProviderClientOptions, ...args: infer P) => infer R ? (...args: P) => R : undefined; }, undefined>;
    signIn: OmitBySpecificTypeValue<{ [K in keyof U]: U[K]["signIn"] extends (options: ProviderClientOptions, ...args: infer P) => infer R ? (...args: P) => R : undefined; }, undefined>;
    signOut(): Promise<void>;
    getSession(): Promise<TokenPayloadInput<InferSessionUser<T>> | undefined>;
    getCsrfToken(): Promise<string>;
}
