import * as cookie from 'cookie';
import { Hono } from 'hono';
import { v4 as uuidv4 } from 'uuid';
import { Monban, Provider, type Profile, type Providers } from '../../main';

export type OAuth2Tokens = {
    access_token?: string;
    refresh_token?: string;
};

export class OAuth2Provider<T extends Profile, U extends OAuth2Tokens> extends Provider<T> {
    protected authorizationUrl: string;
    protected tokenUrl: string;
    protected scope?: string;
    protected clientId: string;
    protected clientSecret: string;
    protected getProfile: (tokens: U) => Promise<T | undefined>;

    constructor(options: {
        authorizationUrl: string;
        tokenUrl: string;
        scope?: string;
        clientId: string;
        clientSecret: string;
        getProfile: (tokens: U) => Promise<T | undefined>;
    }) {
        super();

        this.authorizationUrl = options.authorizationUrl;
        this.tokenUrl = options.tokenUrl;
        this.scope = options.scope;
        this.clientId = options.clientId;
        this.clientSecret = options.clientSecret;
        this.getProfile = options.getProfile;
    }

    getAuthUrl(callbackUrl: string, redirectUrl: string, stateId: string) {
        const params = new URLSearchParams({
            response_type: 'code',
            client_id: this.clientId,
            redirect_uri: callbackUrl,
            state: encodeURIComponent(
                JSON.stringify({
                    stateId,
                    redirect: redirectUrl,
                }),
            ),
        });

        if (this.scope !== undefined) {
            params.set('scope', this.scope);
        }

        const url = new URL(this.authorizationUrl);
        url.search = params.toString();

        return url.toString();
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    async authenticate(req: Request, callbackUrl: string) {
        const code = new URL(req.url).searchParams.get('code') ?? '';

        try {
            const params = new URLSearchParams({
                grant_type: 'authorization_code',
                redirect_uri: callbackUrl,
                client_id: this.clientId,
                client_secret: this.clientSecret,
                code,
            });
            const res = await fetch(this.tokenUrl, {
                method: 'post',
                headers: {
                    'content-type': 'application/x-www-form-urlencoded',
                },
                body: params,
            });

            if (!res.ok) {
                const body = await res.text();

                throw body;
            }

            const tokens = (await res.json()) as U;
            const profile = await this.getProfile(tokens);

            if (profile === undefined) {
                throw new Error('Invalid token');
            }

            return profile;
        } catch (e) {
            return undefined;
        }
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    async handleRequest(req: Request, endpoint: string, monban: Monban<any, Providers<T>>) {
        const app = new Hono().basePath(endpoint);
        const callbackUrl = `${new URL(req.url).origin}${endpoint}/callback`;

        app.get('/signin', async (c) => {
            const location = c.req.query('location') ?? new URL(c.req.url).origin;
            const redirectUrl = c.req.query('redirect') ?? location;
            const stateId = uuidv4();
            const authUrl = this.getAuthUrl(callbackUrl, redirectUrl, stateId);

            const setCookie = cookie.serialize('_monban_oauth2_state', stateId, {
                ...monban.cookieOptions,
                maxAge: undefined,
            });
            c.header('set-cookie', setCookie);

            return c.redirect(authUrl);
        });

        app.get('/callback', async (c) => {
            let authState: {
                stateId: string;
                redirect: string;
            };

            try {
                const authStateStr = c.req.query('state') ?? '';
                authState = JSON.parse(decodeURIComponent(authStateStr));

                const sessionState = c.req.cookie('_monban_oauth2_state');

                if (authState.stateId !== sessionState) {
                    throw new Error('Invalid state');
                }
            } catch (e) {
                return c.redirect(`${endpoint}/signin`);
            }

            const profile = await this.authenticate(c.req.raw, callbackUrl);

            if (profile === undefined) {
                return c.redirect(`${endpoint}/signin`);
            }

            const session = await monban.createSession(profile);
            const setCookie = await monban.createSessionCookie(session);
            c.header('set-cookie', setCookie);

            return c.redirect(authState.redirect);
        });

        const res = await app.fetch(req);

        return res;
    }
}
