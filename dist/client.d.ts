import { InferSessionUser, Monban, TokenPayloadInput } from './main';
import { KeyOfSpecificTypeValue, OmitBySpecificTypeValue } from './types';
export type ProviderClientOptions = {
    endpoint: string;
    csrfToken: string;
};
export declare abstract class ProviderClient {
    signUp?(options: ProviderClientOptions, ...args: any): Promise<any>;
    abstract signIn(options: ProviderClientOptions, ...args: any): Promise<any>;
}
export type ProviderClientMethods = KeyOfSpecificTypeValue<ProviderClient, ((...args: any) => any) | undefined>;
export type ProviderClients<T> = {
    [K in keyof T]: T[K] extends ProviderClient ? T[K] : never;
};
export type OnSessionChangeCallback<T extends Monban<any, any>> = (session: TokenPayloadInput<InferSessionUser<T>> | undefined) => void;
export declare class MonbanClient<T extends Monban<any, any>, U = unknown> {
    protected endpoint: string;
    protected providerClients: ProviderClients<U>;
    protected onSessionChangeCallbacks: OnSessionChangeCallback<T>[];
    constructor(endpoint: string, providerClients: ProviderClients<U>);
    protected triggerOnSessionChange(callback?: OnSessionChangeCallback<T>): Promise<void>;
    onSessionChange(callback: OnSessionChangeCallback<T>): void;
    protected createProviderMethodProxy<V extends ProviderClientMethods>(method: V): OmitBySpecificTypeValue<ProviderClients<U> extends infer T_1 ? { [K in keyof T_1]: ProviderClients<U>[K][V] extends (options: ProviderClientOptions, ...args: infer P) => infer R ? (...args: P) => R : undefined; } : never, undefined>;
    signUp: OmitBySpecificTypeValue<ProviderClients<U> extends infer T_1 ? { [K in keyof T_1]: ProviderClients<U>[K]["signUp"] extends (options: ProviderClientOptions, ...args: infer P) => infer R ? (...args: P) => R : undefined; } : never, undefined>;
    signIn: OmitBySpecificTypeValue<ProviderClients<U> extends infer T_1 ? { [K in keyof T_1]: ProviderClients<U>[K]["signIn"] extends (options: ProviderClientOptions, ...args: infer P) => infer R ? (...args: P) => R : undefined; } : never, undefined>;
    signOut(): Promise<void>;
    getSession(): Promise<TokenPayloadInput<InferSessionUser<T>> | undefined>;
    getCsrfToken(): Promise<string>;
}
