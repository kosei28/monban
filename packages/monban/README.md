# Monban

**Monban** - _\[門番\] means Gatekeeper in Japanese_ - is a simple authentication library for TypeScript that works with any framework or runtime.

## Features

-   **Simple and Lightweight**
-   **Framework agnostic**: Works with any framework such as Express or Next.js
-   **Runtime agnostic**: Works with any runtime such as Cloudflare Workers
-   **No User Management**: Users can be managed in any database
-   **Client library provided**: Easy to implement in frontend

## Quick Start

### Install

```bash
npm install monban
```

### Server

```typescript
import { Monban } from 'monban';
import { GoogleProvider } from 'monban/providers/google/server';

export type User = {
    id: string;
    name: string;
    email: string;
    picture: string;
};

const monban = new Monban(
    {
        google: new GoogleProvider({
            clientId: 'GOOGLE_CLIENT_ID',
            clientSecret: 'GOOGLE_CLIENT_SECRET',
        }),
    },
    {
        secret: 'JWT_SECRET',
        maxAge: 60 * 60 * 24 * 30,
        callbacks: {
            async getUser(profile) {
                const user: User = {
                    id: profile.id,
                    name: profile.name,
                    email: profile.email,
                    picture: profile.picture,
                };

                return user;
            },
        },
    },
);

export default {
    async fetch(request: Request): Promise<Response> {
        return monban.handleRequest(request, '/monban');
    },
};
```

### Client

```typescript
import type { User } from './server.ts';
import { MonbanClient } from 'monban/client';
import { GoogleClient } from 'monban/providers/google/client';

const providerClients = {
    google: new GoogleClient(),
};

const monbanClient = new MonbanClient<User, typeof providerClients>('/monban', providerClients);

monbanClient.onSessionChange((session) => {
    console.log(session);
});
```

## Documentation

-   [Server](/packages/monban/docs/server.md)
-   [Client](/packages/monban/docs/client.md)
