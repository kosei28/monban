import { SessionStore } from '.';
declare global {
    var monbanSession: {
        [id: string]: string;
    } | undefined;
}
export declare class MemorySessionStore extends SessionStore {
    create(userId: string): Promise<string>;
    get(sessionId: string): Promise<string | undefined>;
    delete(sessionId: string): Promise<void>;
}
