"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.JsonProvider = void 0;
const hono_1 = require("hono");
const main_1 = require("../../main");
class JsonProvider extends main_1.Provider {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    async handleRequest(req, endpoint, monban) {
        const app = new hono_1.Hono().basePath(endpoint);
        app.post('/signin', async (c) => {
            const profile = {
                provider: 'json',
                ...(await req.json()),
            };
            const session = await monban.createSession(profile);
            const setCookie = await monban.createSessionCookie(session);
            c.header('set-cookie', setCookie);
            return c.json(undefined);
        });
        const res = await app.fetch(req);
        return res;
    }
}
exports.JsonProvider = JsonProvider;
//# sourceMappingURL=server.js.map