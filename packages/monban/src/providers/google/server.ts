import { OAuth2Provider } from '../oauth2/server';

export type GoogleProfile = {
    provider: 'google';
    id: string;
    name: string;
    email: string;
    picture: string;
    tokens: GoogleTokens;
};

export type GoogleTokens = {
    access_token?: string;
    refresh_token?: string;
    id_token?: string;
    expiry_date?: number;
    token_type?: string;
    scope?: string;
};

export class GoogleProvider extends OAuth2Provider<GoogleProfile, GoogleTokens> {
    constructor(options: { clientId: string; clientSecret: string }) {
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

                    const profile: GoogleProfile = {
                        provider: 'google',
                        id: raw.sub,
                        name: raw.name,
                        email: raw.email,
                        picture: raw.picture,
                        tokens,
                    };

                    return profile;
                } catch (e) {
                    return undefined;
                }
            },
        });
    }
}
