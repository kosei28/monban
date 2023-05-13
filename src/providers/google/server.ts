import { Auth, google } from 'googleapis';
import { Hono } from 'hono';
import { Monban, SessionUserBase, Provider } from '../../main';

type GoogleAccountInfo = {
    id: string;
    name: string;
    email: string;
    picture: string;
    tokens: Auth.Credentials;
    provider: 'google';
};

export class GoogleProvider<T extends SessionUserBase> extends Provider<T, GoogleAccountInfo> {
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

    async authenticate(req: Request, callbackUrl: string) {
        const client = new google.auth.OAuth2(this.clientId, this.clientSecret, callbackUrl);
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
                    tokens,
                    provider: 'google',
                } as GoogleAccountInfo;
            }
        } catch (e) {
            return undefined;
        }
    }

    async handleSignIn(req: Request, endpoint: string, monban: Monban<T, GoogleAccountInfo>) {
        const app = new Hono().basePath(endpoint);
        const callbackUrl = `${new URL(req.url).origin}${endpoint}/callback`;

        app.get('/', async (c) => {
            const authUrl = this.getAuthUrl(callbackUrl);

            return c.redirect(authUrl);
        });

        app.get('/callback', async (c) => {
            const accountInfo = await this.authenticate(c.req.raw, callbackUrl);

            if (accountInfo === undefined) {
                return c.redirect(endpoint);
            }

            const userId = await monban.createUser(accountInfo);
            const session = await monban.createSession(accountInfo, userId);

            const setCookie = await monban.getSetCookie(session);
            c.header('set-cookie', setCookie);

            return c.redirect('/');
        });

        const res = await app.fetch(req);

        return res;
    }
}
