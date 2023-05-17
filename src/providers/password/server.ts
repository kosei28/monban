import { Hono } from 'hono';
import { Monban, Provider, Providers } from '../../main';

type PasswordAuthInfo = {
    id: string;
    email: string;
    password: string;
    provider: 'password';
};

export class PasswordProvider extends Provider<PasswordAuthInfo> {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    async authenticate(req: Request, monban: Monban<any, Providers<PasswordAuthInfo>>) {
        try {
            const { email, password } = await req.json();

            if (email === undefined || password === undefined) {
                return undefined;
            }

            const authInfo = {
                id: email,
                email: email,
                password: password,
                provider: 'password',
            } as PasswordAuthInfo;

            const userId = await monban.verifyUser(authInfo);

            return {
                authInfo,
                userId,
            };
        } catch (e) {
            return undefined;
        }
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    async handleRequest(req: Request, endpoint: string, monban: Monban<any, Providers<PasswordAuthInfo>>) {
        const app = new Hono().basePath(endpoint);

        app.post('/signup', async (c) => {
            const auth = await this.authenticate(c.req.raw, monban);

            if (auth === undefined || auth.userId !== undefined) {
                c.status(400);

                return c.json(undefined);
            }

            auth.userId = await monban.createAccount(auth.authInfo);

            const payload = await monban.createToken(auth.userId, auth.authInfo);
            const token = monban.encodeToken(payload);
            const setCookie = await monban.getTokenSetCookie(token);
            c.header('set-cookie', setCookie);

            return c.json(undefined);
        });

        app.post('/signin', async (c) => {
            const auth = await this.authenticate(c.req.raw, monban);

            if (auth === undefined || auth.userId === undefined) {
                c.status(401);

                return c.json(undefined);
            }

            const payload = await monban.createToken(auth.userId, auth.authInfo);
            const token = monban.encodeToken(payload);
            const setCookie = await monban.getTokenSetCookie(token);
            c.header('set-cookie', setCookie);

            return c.json(undefined);
        });

        const res = await app.fetch(req);

        return res;
    }
}
