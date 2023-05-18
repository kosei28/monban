"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PasswordClient = void 0;
const client_1 = require("../../client");
class PasswordClient extends client_1.ProviderClient {
    async signUp(options, email, password) {
        try {
            await fetch(`${options.endpoint}/providers/${options.provider}/signup`, {
                method: 'post',
                headers: {
                    'content-type': 'application/json',
                    'x-monban-csrf-token': options.csrfToken,
                },
                body: JSON.stringify({
                    email,
                    password,
                }),
            });
            return true;
        }
        catch (e) {
            return false;
        }
    }
    async signIn(options, email, password) {
        try {
            await fetch(`${options.endpoint}/providers/${options.provider}/signin`, {
                method: 'post',
                headers: {
                    'content-type': 'application/json',
                    'x-monban-csrf-token': options.csrfToken,
                },
                body: JSON.stringify({
                    email,
                    password,
                }),
            });
            return true;
        }
        catch (e) {
            return false;
        }
    }
}
exports.PasswordClient = PasswordClient;
//# sourceMappingURL=client.js.map