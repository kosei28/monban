"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.GoogleClient = void 0;
const client_1 = require("../../client");
class GoogleClient extends client_1.ProviderClient {
    async signIn(endpoint) {
        location.href = `${endpoint}/signin/google`;
    }
}
exports.GoogleClient = GoogleClient;
//# sourceMappingURL=client.js.map