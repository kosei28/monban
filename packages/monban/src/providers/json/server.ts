import { Monban, Provider } from '../../main';

export type JsonProfile<T> = {
    provider: 'json';
} & T;

export class JsonProvider<T> extends Provider<JsonProfile<T>> {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    async handleRequest(req: Request, endpoint: string, monban: Monban<any, any>) {
        const url = new URL(req.url);

        if (!url.pathname.startsWith(endpoint)) {
            return new Response(undefined, {
                status: 404,
            });
        }

        const pathnames = url.pathname
            .slice(endpoint.length)
            .split('/')
            .filter((pathname) => pathname !== '');

        if (pathnames[0] === 'signin' && req.method === 'POST') {
            const profile = {
                provider: 'json',
                ...(await req.json()),
            } as JsonProfile<T>;

            const session = await monban.createSession(profile);
            const setCookie = await monban.createSessionCookie(session);

            return new Response(undefined, {
                headers: {
                    'set-cookie': setCookie,
                },
            });
        } else {
            return new Response(undefined, {
                status: 404,
            });
        }
    }
}
