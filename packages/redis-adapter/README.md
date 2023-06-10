# `@monban/redis-adapter`

## Installation

```bash
npm install @monban/redis-adapter
```

## Usage

```typescript
import { Monban } from 'monban';
import { RedisAdapter } from '@monban/redis-adapter';
import { Redis } from 'ioredis';

const monban = new Monban(providers, {
    ...options,
    adapter: new RedisAdapter({
        session: new Redis(),
        userSession: new Redis(),
    }),
});
```
