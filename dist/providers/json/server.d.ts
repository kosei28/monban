import { Monban, Provider } from '../../main';
export type JsonProfile<T> = {
    provider: 'json';
} & T;
export declare class JsonProvider<T> extends Provider<JsonProfile<T>> {
    handleRequest(req: Request, endpoint: string, monban: Monban<any, any>): Promise<Response>;
}
