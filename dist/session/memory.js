"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MemorySessionStore = void 0;
const uuid_1 = require("uuid");
const _1 = require(".");
class MemorySessionStore extends _1.SessionStore {
    async create(userId) {
        const sessionId = (0, uuid_1.v4)();
        if (globalThis.monbanSession === undefined) {
            globalThis.monbanSession = {};
        }
        globalThis.monbanSession[sessionId] = userId;
        return sessionId;
    }
    async get(sessionId) {
        if (globalThis.monbanSession === undefined) {
            return undefined;
        }
        const userId = globalThis.monbanSession[sessionId];
        if (userId === undefined) {
            return undefined;
        }
        return userId;
    }
    async delete(sessionId) {
        if (globalThis.monbanSession !== undefined) {
            delete globalThis.monbanSession[sessionId];
        }
    }
}
exports.MemorySessionStore = MemorySessionStore;
//# sourceMappingURL=memory.js.map