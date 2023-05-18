"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.OAuth2Provider = void 0;
const hono_1 = require("hono");
const main_1 = require("../../main");
class OAuth2Provider extends main_1.Provider {
    authorizationUrl;
    tokenUrl;
    scope;
    clientId;
    clientSecret;
    getProfile;
    constructor(options) {
        super();
        this.authorizationUrl = options.authorizationUrl;
        this.tokenUrl = options.tokenUrl;
        this.scope = options.scope;
        this.clientId = options.clientId;
        this.clientSecret = options.clientSecret;
        this.getProfile = options.getProfile;
    }
    getAuthUrl(callbackUrl, redirectUrl) {
        const params = new URLSearchParams({
            response_type: 'code',
            client_id: this.clientId,
            redirect_uri: callbackUrl,
            state: encodeURIComponent(JSON.stringify({
                redirect: redirectUrl,
            })),
        });
        // TODO: add state for CSRF protection
        if (this.scope !== undefined) {
            params.set('scope', this.scope);
        }
        const url = new URL(this.authorizationUrl);
        url.search = params.toString();
        return url.toString();
    }
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    async authenticate(req, callbackUrl, monban) {
        const code = new URL(req.url).searchParams.get('code') ?? '';
        // TODO: check state for CSRF protection
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
            const tokens = (await res.json());
            const profile = await this.getProfile(tokens);
            if (profile !== undefined) {
                const userId = await monban.verifyUser(profile);
                return {
                    profile,
                    userId,
                };
            }
            return undefined;
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
            const location = c.req.query('location') ?? new URL(c.req.url).origin;
            const redirectUrl = c.req.query('redirect') ?? location;
            const authUrl = this.getAuthUrl(callbackUrl, redirectUrl);
            return c.redirect(authUrl);
        });
        app.get('/callback', async (c) => {
            const auth = await this.authenticate(c.req.raw, callbackUrl, monban);
            if (auth === undefined) {
                return c.redirect(`${endpoint}/signin`);
            }
            if (auth.userId === undefined) {
                auth.userId = await monban.createAccount(auth.profile);
            }
            const payload = await monban.createToken(auth.userId, auth.profile);
            const token = monban.encodeToken(payload);
            const setCookie = await monban.getTokenSetCookie(token);
            c.header('set-cookie', setCookie);
            let redirectUrl;
            try {
                const authStateStr = c.req.query('state') ?? '';
                const authState = JSON.parse(decodeURIComponent(authStateStr));
                redirectUrl = authState.redirect ?? new URL(c.req.url).origin;
            }
            catch (e) {
                redirectUrl = new URL(c.req.url).origin;
            }
            return c.redirect(redirectUrl);
        });
        const res = await app.fetch(req);
        return res;
    }
}
exports.OAuth2Provider = OAuth2Provider;
//# sourceMappingURL=server.js.map