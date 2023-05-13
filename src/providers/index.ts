import { Monban, SessionUserBase } from '../main';

export type AccountInfoBase = {
    name: string;
    email: string;
    provider: string;
};

export type Providers<T extends AccountInfoBase, U extends SessionUserBase> = { [name: string]: Provider<T, U> };

export type InferAccountInfo<T> = T extends Providers<infer U, SessionUserBase> ? U : never;

export abstract class Provider<T extends AccountInfoBase, U extends SessionUserBase> {
    abstract handleSignIn(req: Request, endpoint: string, monban: Monban<T, U>): Promise<Response>;
}

export * from './google';
