import { OAuth2Provider } from '../oauth2/server';

export type GoogleProfile = {
    provider: 'google';
    id: string;
    name: string;
    email: string;
    picture: string;
};

export type GoogleTokens = {
    access_token?: string;
    refresh_token?: string;
    expiry_date?: number;
    token_type?: string;
    id_token?: string;
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

                    const profile = {
                        id: raw.sub,
                        name: raw.name,
                        email: raw.email,
                        picture: raw.picture,
                        provider: 'google',
                    } as GoogleProfile;

                    return profile;
                } catch (e) {
                    return undefined;
                }
            },
        });
    }
}
