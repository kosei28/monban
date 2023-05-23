import type { SessionUser, TokenPayloadInput } from './main';
import type { KeyOfSpecificTypeValue, OmitBySpecificTypeValue } from './types';
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
export type OnSessionChangeCallback<T extends SessionUser> = (session: TokenPayloadInput<T> | undefined) => void;
export declare class MonbanClient<T extends SessionUser, U extends ProviderClients> {
    protected endpoint: string;
    protected providerClients: U;
    protected onSessionChangeCallbacks: OnSessionChangeCallback<T>[];
    constructor(endpoint: string, providerClients: U);
    protected triggerOnSessionChange(callback?: OnSessionChangeCallback<T>): Promise<void>;
    onSessionChange(callback: OnSessionChangeCallback<T>): Promise<void>;
    protected createProviderMethodProxy<V extends ProviderClientMethods>(method: V): OmitBySpecificTypeValue<{ [K in keyof U]: U[K][V] extends (options: ProviderClientOptions, ...args: infer P) => infer R ? (...args: P) => R : undefined; }, undefined>;
    signUp: OmitBySpecificTypeValue<{ [K in keyof U]: U[K]["signUp"] extends (options: ProviderClientOptions, ...args: infer P) => infer R ? (...args: P) => R : undefined; }, undefined>;
    signIn: OmitBySpecificTypeValue<{ [K in keyof U]: U[K]["signIn"] extends (options: ProviderClientOptions, ...args: infer P) => infer R ? (...args: P) => R : undefined; }, undefined>;
    signOut(): Promise<void>;
    getSession(): Promise<TokenPayloadInput<T> | undefined>;
    getCsrfToken(): Promise<string>;
}
