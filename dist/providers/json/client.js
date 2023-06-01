"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.JsonClient = void 0;
const client_1 = require("../../client");
class JsonClient extends client_1.ProviderClient {
    async signIn(options, body) {
        try {
            await fetch(`${options.endpoint}/providers/${options.provider}/signin`, {
                method: 'post',
                headers: {
                    'content-type': 'application/json',
                    'x-monban-csrf-token': options.csrfToken,
                },
                body: JSON.stringify(body),
            });
            return true;
        }
        catch (e) {
            return false;
        }
    }
}
exports.JsonClient = JsonClient;
//# sourceMappingURL=client.js.map