"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MonbanClient = exports.ProviderClient = void 0;
class ProviderClient {
}
exports.ProviderClient = ProviderClient;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
class MonbanClient {
    endpoint;
    providerClients;
    onSessionChangeCallbacks = [];
    async triggerOnSessionChange(callback) {
        const session = await this.getSession();
        if (callback !== undefined) {
            callback(session);
        }
        else {
            this.onSessionChangeCallbacks.forEach((callback) => {
                callback(session);
            });
        }
    }
    constructor(endpoint, providerClients) {
        this.endpoint = endpoint;
        this.providerClients = providerClients;
    }
    onSessionChange(callback) {
        this.triggerOnSessionChange(callback);
        this.onSessionChangeCallbacks.push(callback);
    }
    signIn = new Proxy({}, {
        get: (target, provider) => {
            if (typeof provider !== 'string') {
                return undefined;
            }
            const providerClient = this.providerClients[provider];
            if (providerClient === undefined) {
                return undefined;
            }
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            return async (...args) => {
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                await providerClient.signIn(this.endpoint, ...args);
                await this.triggerOnSessionChange();
            };
        },
    });
    async signOut() {
        await fetch(`${this.endpoint}/signout`);
        await this.triggerOnSessionChange();
    }
    async getSession() {
        const res = await fetch(`${this.endpoint}/session`);
        try {
            const session = (await res.json());
            return session;
        }
        catch (e) {
            return undefined;
        }
    }
    async getUser() {
        const res = await fetch(`${this.endpoint}/user`);
        try {
            const user = (await res.json());
            return user;
        }
        catch (e) {
            return undefined;
        }
    }
    async resetCsrfToken() {
        const res = await fetch(`${this.endpoint}/csrf`);
        const { token } = (await res.json());
        localStorage.setItem('_monbanCsrfToken', token);
        return token;
    }
    async getCsrfToken() {
        const token = localStorage.getItem('_monbanCsrfToken');
        if (token !== null) {
            return token;
        }
        else {
            const token = await this.resetCsrfToken();
            return token;
        }
    }
}
exports.MonbanClient = MonbanClient;
//# sourceMappingURL=client.js.map