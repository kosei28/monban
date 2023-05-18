import { Auth, google } from 'googleapis';
import { Hono } from 'hono';
import { Monban, Provider, Providers } from '../../main';

type GoogleAuthInfo = {
    id: string;
    name: string;
    email: string;
    picture: string;
    tokens: Auth.Credentials;
    provider: 'google';
};

export class GoogleProvider extends Provider<GoogleAuthInfo> {
    protected clientId: string;
    protected clientSecret: string;

    constructor(option: { clientId: string; clientSecret: string }) {
        super();

        this.clientId = option.clientId;
        this.clientSecret = option.clientSecret;
    }

    getAuthUrl(callbackUrl: string, redirectUrl: string) {
        const client = new google.auth.OAuth2(
            this.clientId,
            this.clientSecret,
            `${callbackUrl}?redirect=${redirectUrl}`,
        );
        const url = client.generateAuthUrl({
            access_type: 'online',
            scope: ['profile', 'email'],
        });

        return url;
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    async authenticate(req: Request, callbackUrl: string, monban: Monban<any, Providers<GoogleAuthInfo>>) {
        const client = new google.auth.OAuth2(this.clientId, this.clientSecret, callbackUrl);
        const code = new URL(req.url).searchParams.get('code') ?? '';

        try {
            const { tokens } = await client.getToken(code);
            const ticket = await client.verifyIdToken({ idToken: tokens.id_token ?? '' });
            const payload = ticket.getPayload();

            if (payload === undefined) {
                return undefined;
            } else {
                const authInfo = {
                    id: payload.sub,
                    name: payload.name,
                    email: payload.email,
                    picture: payload.picture,
                    tokens,
                    provider: 'google',
                } as GoogleAuthInfo;

                const userId = await monban.verifyUser(authInfo);

                return {
                    authInfo,
                    userId,
                };
            }
        } catch (e) {
            return undefined;
        }
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    async handleRequest(req: Request, endpoint: string, monban: Monban<any, Providers<GoogleAuthInfo>>) {
        const app = new Hono().basePath(endpoint);
        const callbackUrl = `${new URL(req.url).origin}${endpoint}/callback`;

        app.get('/signin', async (c) => {
            const redirectUrl = c.req.query('redirect') ?? c.req.url;
            const authUrl = this.getAuthUrl(callbackUrl, redirectUrl);

            return c.redirect(authUrl);
        });

        app.get('/callback', async (c) => {
            const auth = await this.authenticate(c.req.raw, callbackUrl, monban);

            if (auth === undefined) {
                return c.redirect(`${endpoint}/signin`);
            }

            if (auth.userId === undefined) {
                auth.userId = await monban.createAccount(auth.authInfo);
            }

            const payload = await monban.createToken(auth.userId, auth.authInfo);
            const token = monban.encodeToken(payload);
            const setCookie = await monban.getTokenSetCookie(token);
            c.header('set-cookie', setCookie);

            const redirectUrl = c.req.query('redirect') ?? c.req.url;

            return c.redirect(redirectUrl);
        });

        const res = await app.fetch(req);

        return res;
    }
}
