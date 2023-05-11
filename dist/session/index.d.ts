export declare abstract class SessionStore {
    abstract create(userId: string): Promise<string>;
    abstract get(sessionId: string): Promise<string | undefined>;
    abstract delete(sessionId: string): Promise<void>;
}
export { MemorySessionStore } from './memory';
