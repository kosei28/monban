"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.JsonProvider = void 0;
const hono_1 = require("hono");
const main_1 = require("../../main");
class JsonProvider extends main_1.Provider {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    async authenticate(req, monban) {
        try {
            const profile = {
                provider: 'json',
                ...(await req.json()),
            };
            const userId = await monban.verifyUser(profile);
            return {
                profile,
                userId,
            };
        }
        catch (e) {
            return undefined;
        }
    }
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    async handleRequest(req, endpoint, monban) {
        const app = new hono_1.Hono().basePath(endpoint);
        app.post('/signup', async (c) => {
            const auth = await this.authenticate(c.req.raw, monban);
            if (auth === undefined || auth.userId !== undefined) {
                c.status(400);
                return c.json(undefined);
            }
            auth.userId = await monban.createAccount(auth.profile);
            const payload = await monban.createToken(auth.userId, auth.profile);
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
            const payload = await monban.createToken(auth.userId, auth.profile);
            const token = monban.encodeToken(payload);
            const setCookie = await monban.getTokenSetCookie(token);
            c.header('set-cookie', setCookie);
            return c.json(undefined);
        });
        const res = await app.fetch(req);
        return res;
    }
}
exports.JsonProvider = JsonProvider;
//# sourceMappingURL=server.js.map