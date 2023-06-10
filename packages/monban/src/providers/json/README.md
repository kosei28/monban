# `JsonProvider`

```typescript
import { JsonProvider } from 'monban/providers/json/server';
```

## `new JsonProvider()`

Creates a JsonProvider instance.

```typescript
type Profile = {
    email: string;
    password: string;
};

const jsonProvider = new JsonProvider<Profile>();
```

# `JsonClient`

```typescript
import { JsonClient } from 'monban/providers/json/client';
```

## `new JsonClient()`

Creates a JsonClient instance.

```typescript
const providerClients = {
    json: new JsonClient<Profile>(),
};

const monbanClient = new MonbanClient<User, typeof providerClients>('/monban', providerClients);
```

## `signIn`

Signs in with a profile.

```typescript
const body: Profile = {
    email: '...',
    password: '...',
};

const success: boolean = monbanClient.signIn.json(body);
```
