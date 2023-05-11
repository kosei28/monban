import { Monban } from '../main';

export type AccountInfoBase = {
    name: string;
    email: string;
    provider: string;
};

export type Providers<T extends AccountInfoBase> = { [name: string]: Provider<T> };

export type InferAccountInfo<T> = T extends Providers<infer U> ? U : never;

export abstract class Provider<T extends AccountInfoBase> {
    abstract handleLogin(req: Request, endpoint: string, monban: Monban<T>): Promise<Response>;
}

export { GoogleProvider } from './google';
