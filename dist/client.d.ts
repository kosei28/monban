import { InferSessionUser, InferUser, Monban, Session } from './main';
export declare abstract class ProviderClient {
    abstract signIn(endpoint: string): Promise<void>;
}
export type ProviderClients = {
    [key: string]: ProviderClient;
};
export type OnSessionChangeCallback<T extends Monban<any, any, any>> = (session: Session<InferSessionUser<T>> | undefined) => void;
export declare class MonbanClient<T extends Monban<any, any, any>, U extends ProviderClients> {
    protected endpoint: string;
    protected providerClients: U;
    protected onSessionChangeCallbacks: OnSessionChangeCallback<T>[];
    protected triggerOnSessionChange(callback?: OnSessionChangeCallback<T>): Promise<void>;
    constructor(endpoint: string, providerClients: U);
    onSessionChange(callback: OnSessionChangeCallback<T>): void;
    signIn: { [key in keyof U]: U[key]["signIn"]; };
    signOut(): Promise<void>;
    getSession(): Promise<Session<InferSessionUser<T>>>;
    getUser(): Promise<InferUser<T>>;
    resetCsrfToken(): Promise<string>;
    getCsrfToken(): Promise<string>;
}