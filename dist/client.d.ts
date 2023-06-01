import type { Session } from './main';
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
export type OnSessionChangeCallback = (session: Session | undefined) => void;
export declare class MonbanClient<T extends ProviderClients> {
    protected endpoint: string;
    protected providerClients: T;
    protected onSessionChangeCallbacks: OnSessionChangeCallback[];
    constructor(endpoint: string, providerClients: T);
    protected triggerOnSessionChange(callback?: OnSessionChangeCallback): Promise<void>;
    onSessionChange(callback: OnSessionChangeCallback): Promise<void>;
    protected createProviderMethodProxy<V extends ProviderClientMethods>(method: V): OmitBySpecificTypeValue<{ [K in keyof T]: T[K][V] extends (options: ProviderClientOptions, ...args: infer P) => infer R ? (...args: P) => R : undefined; }, undefined>;
    signUp: OmitBySpecificTypeValue<{ [K in keyof T]: T[K]["signUp"] extends (options: ProviderClientOptions, ...args: infer P) => infer R ? (...args: P) => R : undefined; }, undefined>;
    signIn: OmitBySpecificTypeValue<{ [K in keyof T]: T[K]["signIn"] extends (options: ProviderClientOptions, ...args: infer P) => infer R ? (...args: P) => R : undefined; }, undefined>;
    signOut(): Promise<void>;
    getSession(): Promise<Session | undefined>;
    getCsrfToken(): Promise<string>;
}
