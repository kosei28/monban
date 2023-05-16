"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.GoogleClient = void 0;
const client_1 = require("../../client");
class GoogleClient extends client_1.ProviderClient {
    async signIn(options) {
        location.href = `${options.endpoint}/providers/google/signin`;
    }
}
exports.GoogleClient = GoogleClient;
//# sourceMappingURL=client.js.map