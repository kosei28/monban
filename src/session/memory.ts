import { v4 as uuidv4 } from 'uuid';
import { SessionStore } from '.';

declare global {
    // eslint-disable-next-line no-var
    var monbanSession: { [id: string]: string } | undefined;
}

export class MemorySessionStore extends SessionStore {
    async create(userId: string) {
        const sessionId = uuidv4();

        if (globalThis.monbanSession === undefined) {
            globalThis.monbanSession = {};
        }

        globalThis.monbanSession[sessionId] = userId;

        return sessionId;
    }

    async get(sessionId: string) {
        if (globalThis.monbanSession === undefined) {
            return undefined;
        }

        const userId = globalThis.monbanSession[sessionId];

        if (userId === undefined) {
            return undefined;
        }

        return userId;
    }

    async delete(sessionId: string) {
        if (globalThis.monbanSession !== undefined) {
            delete globalThis.monbanSession[sessionId];
        }
    }
}
