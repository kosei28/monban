"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.GoogleProvider = void 0;
const googleapis_1 = require("googleapis");
const hono_1 = require("hono");
const main_1 = require("../../main");
class GoogleProvider extends main_1.Provider {
    clientId;
    clientSecret;
    constructor(option) {
        super();
        this.clientId = option.clientId;
        this.clientSecret = option.clientSecret;
    }
    getAuthUrl(callbackUrl, redirectUrl) {
        const client = new googleapis_1.google.auth.OAuth2(this.clientId, this.clientSecret, callbackUrl);
        const url = client.generateAuthUrl({
            access_type: 'online',
            scope: ['profile', 'email'],
            state: encodeURIComponent(JSON.stringify({
                redirect: redirectUrl,
            })),
        });
        return url;
    }
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    async authenticate(req, callbackUrl, monban) {
        const client = new googleapis_1.google.auth.OAuth2(this.clientId, this.clientSecret, callbackUrl);
        const code = new URL(req.url).searchParams.get('code') ?? '';
        try {
            const { tokens } = await client.getToken(code);
            const ticket = await client.verifyIdToken({ idToken: tokens.id_token ?? '' });
            const payload = ticket.getPayload();
            if (payload === undefined) {
                return undefined;
            }
            else {
                const authInfo = {
                    id: payload.sub,
                    name: payload.name,
                    email: payload.email,
                    picture: payload.picture,
                    tokens,
                    provider: 'google',
                };
                const userId = await monban.verifyUser(authInfo);
                return {
                    authInfo,
                    userId,
                };
            }
        }
        catch (e) {
            return undefined;
        }
    }
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    async handleRequest(req, endpoint, monban) {
        const app = new hono_1.Hono().basePath(endpoint);
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
            let redirectUrl;
            try {
                const authStateStr = c.req.query('state') ?? '';
                const authState = JSON.parse(decodeURIComponent(authStateStr));
                redirectUrl = authState.redirect ?? c.req.url;
            }
            catch (e) {
                redirectUrl = c.req.url;
            }
            return c.redirect(redirectUrl);
        });
        const res = await app.fetch(req);
        return res;
    }
}
exports.GoogleProvider = GoogleProvider;
//# sourceMappingURL=server.js.map