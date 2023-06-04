import type { Redis } from 'ioredis';
import type { Adapter, Session, User } from 'monban';

export class RedisAdapter implements Adapter {
    protected sessionRedis: Redis;
    protected userSessionRedis: Redis;

    constructor(redisClients: { session: Redis; userSession: Redis }) {
        this.sessionRedis = redisClients.session;
        this.userSessionRedis = redisClients.userSession;
    }

    async createSession(session: Session<User>, maxAge: number) {
        const sessionIds = await this.userSessionRedis.lrange(session.user.id, 0, -1);

        await Promise.all(
            sessionIds.map(async (sessionId) => {
                if (!(await this.verifySession(sessionId))) {
                    this.userSessionRedis.lrem(session.user.id, 0, sessionId);
                }
            }),
        );

        await Promise.all([
            this.sessionRedis.set(session.id, JSON.stringify(session), 'EX', maxAge),
            this.userSessionRedis.lpush(session.user.id, session.id),
        ]);
    }

    async verifySession(sessionId: string) {
        const storedSession = await this.sessionRedis.get(sessionId);

        if (storedSession === null) {
            return false;
        }

        return true;
    }

    async extendSession(sessionId: string, maxAge: number) {
        await this.sessionRedis.expire(sessionId, maxAge);
    }

    async invalidateSession(sessionId: string) {
        await this.sessionRedis.del(sessionId);
    }

    async invalidateUserSessions(userId: string) {
        const sessionIds = await this.userSessionRedis.lrange(userId, 0, -1);

        await Promise.all([this.sessionRedis.del(...sessionIds), this.userSessionRedis.del(userId)]);
    }
}
