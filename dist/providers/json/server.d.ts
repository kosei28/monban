import { Monban, Provider } from '../../main';
export type JsonProfile<T> = {
    provider: 'json';
} & T;
export declare class JsonProvider<T> extends Provider<JsonProfile<T>> {
    authenticate(req: Request, monban: Monban<any>): Promise<{
        profile: JsonProfile<T>;
        userId: string | undefined;
    } | undefined>;
    handleRequest(req: Request, endpoint: string, monban: Monban<any>): Promise<Response>;
}
