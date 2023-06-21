# `GoogleProvider`

```typescript
import { GoogleProvider } from 'monban/providers/google/server';
```

## `new GoogleProvider(options)`

Creates a Google provider instance.

```typescript
const googleProvider = new GoogleProvider({
    clientId: 'GOOGLE_CLIENT_ID',
    clientSecret: 'GOOGLE_CLIENT_SECRET',
});
```

> **Note**
>
> The callback url required for configuration at the provider is `{endpoint}/providers/google/callback`.

### `options`

#### `clientId: string`

The client ID.

#### `clientSecret: string`

The client secret.

# `GoogleClient`

```typescript
import { GoogleClient } from 'monban/providers/google/client';
```

## `new GoogleClient()`

Creates an Google client instance.

```typescript
const providerClients = {
    google: new GoogleClient(),
};

const monbanClient = new MonbanClient<User, typeof providerClients>('/monban', providerClients);
```

## `signIn`

Signs in with Google.

```typescript
await monbanClient.signIn.google(redirectUrl);
```

### `redirectUrl?: string`

default: `undefined`

The redirect URL.
If undefined is set, it will redirect to the current URL.
