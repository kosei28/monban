"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.GoogleClient = void 0;
const client_1 = require("../../client");
class GoogleClient extends client_1.ProviderClient {
    async signIn(options, redirectUrl) {
        let url = `${options.endpoint}/providers/google/signin`;
        if (redirectUrl !== undefined) {
            url += `?redirect=${redirectUrl}`;
        }
        location.href = url;
    }
}
exports.GoogleClient = GoogleClient;
//# sourceMappingURL=client.js.map