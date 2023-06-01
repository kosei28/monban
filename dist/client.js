"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MonbanClient = exports.ProviderClient = void 0;
const cookie = require("cookie");
class ProviderClient {
}
exports.ProviderClient = ProviderClient;
class MonbanClient {
    endpoint;
    providerClients;
    onSessionChangeCallbacks = [];
    addedFocusEventListener = false;
    constructor(endpoint, providerClients) {
        this.endpoint = endpoint;
        this.providerClients = providerClients;
    }
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
    onSessionChange(callback) {
        if (!this.addedFocusEventListener) {
            this.addedFocusEventListener = true;
            window.addEventListener('focus', () => {
                this.triggerOnSessionChange();
            });
        }
        this.onSessionChangeCallbacks.push(callback);
        this.triggerOnSessionChange(callback);
        const unsubscribe = () => {
            this.onSessionChangeCallbacks = this.onSessionChangeCallbacks.filter((c) => c !== callback);
        };
        return unsubscribe;
    }
    createProviderMethodProxy(method) {
        const proxy = new Proxy({}, {
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
                    const result = await providerClient[method]({
                        endpoint: this.endpoint,
                        csrfToken: await this.getCsrfToken(),
                        provider,
                    }, ...args);
                    this.triggerOnSessionChange();
                    return result;
                };
            },
        });
        return proxy;
    }
    signIn = this.createProviderMethodProxy('signIn');
    async signOut() {
        await fetch(`${this.endpoint}/signout`);
        this.triggerOnSessionChange();
    }
    async getSession() {
        try {
            const res = await fetch(`${this.endpoint}/session`);
            const session = (await res.json());
            return session;
        }
        catch (e) {
            return undefined;
        }
    }
    async getCsrfToken() {
        const { _monban_csrf_token: token } = cookie.parse(document.cookie);
        if (token !== undefined) {
            return token;
        }
        else {
            const res = await fetch(`${this.endpoint}/csrf`);
            const { token } = (await res.json());
            return token;
        }
    }
}
exports.MonbanClient = MonbanClient;
//# sourceMappingURL=client.js.map