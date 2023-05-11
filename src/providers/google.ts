import { google } from 'googleapis';
import { Hono } from 'hono';
import { Monban } from '../main';
import { Provider } from '.';

type GoogleAccountInfo = {
    id: string;
    name: string;
    email: string;
    picture: string;
    provider: 'google';
};

export class GoogleProvider extends Provider<GoogleAccountInfo> {
    protected clientId: string;
    protected clientSecret: string;

    constructor(option: { clientId: string; clientSecret: string }) {
        super();

        this.clientId = option.clientId;
        this.clientSecret = option.clientSecret;
    }

    getAuthUrl(callbackUrl: string) {
        const client = new google.auth.OAuth2(this.clientId, this.clientSecret, callbackUrl);
        const url = client.generateAuthUrl({
            access_type: 'online',
            scope: ['profile', 'email'],
        });

        return url;
    }

    async authenticate(req: Request) {
        const client = new google.auth.OAuth2(this.clientId, this.clientSecret, req.url);
        const code = new URL(req.url).searchParams.get('code') ?? '';

        try {
            const { tokens } = await client.getToken(code);
            const ticket = await client.verifyIdToken({ idToken: tokens.id_token ?? '' });
            const payload = ticket.getPayload();

            if (payload === undefined) {
                return undefined;
            } else {
                return {
                    id: payload.sub,
                    name: payload.name,
                    email: payload.email,
                    picture: payload.picture,
                    provider: 'google',
                } as GoogleAccountInfo;
            }
        } catch (e) {
            console.log(e);
            return undefined;
        }
    }

    async handleLogin(req: Request, endpoint: string, monban: Monban<GoogleAccountInfo>) {
        const app = new Hono().basePath(endpoint);

        app.get('/', async (c) => {
            const callbackUrl = `${new URL(c.req.raw.url).origin}${endpoint}/callback`;
            const authUrl = this.getAuthUrl(callbackUrl);

            return c.redirect(authUrl);
        });

        app.get('/callback', async (c) => {
            const accountInfo = await this.authenticate(c.req.raw);

            if (accountInfo === undefined) {
                return c.redirect(endpoint);
            }

            const userId = await monban.createUser(accountInfo);

            const setCookie = await monban.getSetCookie(userId);
            c.header('set-cookie', setCookie);

            return c.redirect('/');
        });

        const res = await app.fetch(req);

        return res;
    }
}
