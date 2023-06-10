# `@monban/upstash-redis-adapter`

## Installation

```bash
npm install @monban/upstash-redis-adapter
```

## Usage

```typescript
import { Monban } from 'monban';
import { UpstashRedisAdapter } from '@monban/upstash-redis-adapter';
import { Redis } from '@upstash/redis';

const monban = new Monban(providers, {
    ...options,
    adapter: new UpstashRedisAdapter({
        session: new Redis({
            url: 'UPSTASH_REDIS_REST_URL',
            token: 'UPSTASH_REDIS_REST_TOKEN',
        }),
        userSession: new Redis({
            url: 'UPSTASH_REDIS_REST_URL',
            token: 'UPSTASH_REDIS_REST_TOKEN',
        }),
    }),
});
```
