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
    getAuthUrl(callbackUrl) {
        const client = new googleapis_1.google.auth.OAuth2(this.clientId, this.clientSecret, callbackUrl);
        const url = client.generateAuthUrl({
            access_type: 'online',
            scope: ['profile', 'email'],
        });
        return url;
    }
    async authenticate(req, callbackUrl) {
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
                return {
                    id: payload.sub,
                    name: payload.name,
                    email: payload.email,
                    picture: payload.picture,
                    tokens,
                    provider: 'google',
                };
            }
        }
        catch (e) {
            return undefined;
        }
    }
    async handleSignIn(req, endpoint, monban) {
        const app = new hono_1.Hono().basePath(endpoint);
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
exports.GoogleProvider = GoogleProvider;
//# sourceMappingURL=server.js.map