"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.OAuth2Client = void 0;
const client_1 = require("../../client");
class OAuth2Client extends client_1.ProviderClient {
    async signIn(options, redirectUrl) {
        let url = `${options.endpoint}/providers/${options.provider}/signin?location=${location.href}`;
        if (redirectUrl !== undefined) {
            url += `&redirect=${redirectUrl}`;
        }
        location.href = url;
    }
}
exports.OAuth2Client = OAuth2Client;
//# sourceMappingURL=client.js.map