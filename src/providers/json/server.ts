import { Hono } from 'hono';
import { Monban, Provider } from '../../main';

export type JsonProfile<T> = {
    provider: 'json';
} & T;

export class JsonProvider<T> extends Provider<JsonProfile<T>> {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    async handleRequest(req: Request, endpoint: string, monban: Monban<any, any>) {
        const app = new Hono().basePath(endpoint);

        app.post('/signin', async (c) => {
            const profile = {
                provider: 'json',
                ...(await req.json()),
            } as JsonProfile<T>;

            const session = await monban.createSession(profile);
            const setCookie = await monban.createSessionCookie(session);
            c.header('set-cookie', setCookie);

            return c.json(undefined);
        });

        const res = await app.fetch(req);

        return res;
    }
}
