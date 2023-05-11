"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.GoogleProvider = void 0;
const googleapis_1 = require("googleapis");
const hono_1 = require("hono");
const main_1 = require("../main");
class GoogleProvider extends main_1.Provider {
    clientId;
    clientSecret;
    callbackUrl;
    client;
    constructor(option) {
        super();
        this.clientId = option.clientId;
        this.clientSecret = option.clientSecret;
        this.callbackUrl = option.callbackUrl;
        this.client = new googleapis_1.google.auth.OAuth2(this.clientId, this.clientSecret, this.callbackUrl);
    }
    getAuthUrl() {
        const url = this.client.generateAuthUrl({
            access_type: 'online',
            scope: ['profile', 'email'],
        });
        return url;
    }
    async authenticate(req) {
        const code = new URL(req.url).searchParams.get('code') ?? '';
        try {
            const { tokens } = await this.client.getToken(code);
            const ticket = await this.client.verifyIdToken({ idToken: tokens.id_token ?? '' });
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
                    provider: 'google',
                };
            }
        }
        catch (e) {
            return undefined;
        }
    }
    async handleLogin(req, endpoint, monban) {
        const app = new hono_1.Hono().basePath(endpoint);
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
exports.GoogleProvider = GoogleProvider;
//# sourceMappingURL=google.js.map