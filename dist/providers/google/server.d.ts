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
    id_token?: string;
    expiry_date?: number;
    token_type?: string;
    scope?: string;
};
export declare class GoogleProvider extends OAuth2Provider<GoogleProfile, GoogleTokens> {
    constructor(options: {
        clientId: string;
        clientSecret: string;
    });
}
