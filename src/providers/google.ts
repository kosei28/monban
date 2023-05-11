import { google, Auth } from 'googleapis';
import { Hono } from 'hono';
import { Monban, Provider } from '../main';

type AccountInfo = {
    id: string;
    name: string;
    email: string;
    picture: string;
    provider: 'google';
};

export class GoogleProvider extends Provider<AccountInfo> {
    protected clientId: string;
    protected clientSecret: string;
    protected callbackUrl: string;
    protected client: Auth.OAuth2Client;

    constructor(option: { clientId: string; clientSecret: string; callbackUrl: string }) {
        super();

        this.clientId = option.clientId;
        this.clientSecret = option.clientSecret;
        this.callbackUrl = option.callbackUrl;
        this.client = new google.auth.OAuth2(this.clientId, this.clientSecret, this.callbackUrl);
    }

    getAuthUrl() {
        const url = this.client.generateAuthUrl({
            access_type: 'online',
            scope: ['profile', 'email'],
        });

        return url;
    }

    async authenticate(req: Request) {
        const code = new URL(req.url).searchParams.get('code') ?? '';

        try {
            const { tokens } = await this.client.getToken(code);
            const ticket = await this.client.verifyIdToken({ idToken: tokens.id_token ?? '' });
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
                } as AccountInfo;
            }
        } catch (e) {
            return undefined;
        }
    }

    async handleLogin(req: Request, endpoint: string, monban: Monban<AccountInfo>) {
        const app = new Hono().basePath(endpoint);

        app.get('/', async (c) => {
            const authUrl = this.getAuthUrl();

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
