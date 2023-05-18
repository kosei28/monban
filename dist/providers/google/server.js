"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.GoogleProvider = void 0;
const server_1 = require("../oauth2/server");
class GoogleProvider extends server_1.OAuth2Provider {
    constructor(options) {
        super({
            authorizationUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
            tokenUrl: 'https://oauth2.googleapis.com/token',
            scope: 'profile email',
            clientId: options.clientId,
            clientSecret: options.clientSecret,
            getProfile: async (tokens) => {
                try {
                    const res = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
                        headers: {
                            Authorization: `Bearer ${tokens.access_token}`,
                        },
                    });
                    const raw = await res.json();
                    const profile = {
                        id: raw.sub,
                        name: raw.name,
                        email: raw.email,
                        picture: raw.picture,
                        provider: 'google',
                    };
                    return profile;
                }
                catch (e) {
                    return undefined;
                }
            },
        });
    }
}
exports.GoogleProvider = GoogleProvider;
//# sourceMappingURL=server.js.map