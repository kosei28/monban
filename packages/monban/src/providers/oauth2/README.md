# `OAuth2Provider`

```typescript
import { OAuth2Provider } from 'monban/providers/oauth2/server';
```

## `new OAuth2Provider(options)`

Creates an OAuth2 provider instance.

```typescript
type Profile = {
    provider: 'provider';
    id: string;
    name: string;
    email: string;
    picture: string;
};

type Tokens = {
    accessToken: string;
    refreshToken: string;
};

const provider = new OAuth2Provider<Profile, Tokens>({
    authorizationUrl: 'https://provider.com/oauth2/authorize',
    tokenUrl: 'https://provider.com/oauth2/token',
    scope: 'profile email',
    clientId: 'PROVIDER_CLIENT_ID',
    clientSecret: 'PROVIDER_CLIENT_SECRET',
    getProfile: async (tokens) => {
        const profile: Profile = await getProviderProfile(tokens.access_token);
        return profile;
    },
});
```

### `options`

#### `authorizationUrl: string`

The authorization URL.

#### `tokenUrl: string`

The token URL.

#### `scope?: string`

default: `undefined`

The scope.

#### `clientId: string`

The client ID.

#### `clientSecret: string`

The client secret.

#### `getProfile: (tokens) => Promise<Profile>`

A function that gets the profile from the tokens.

# `OAuth2Client`

```typescript
import { OAuth2Client } from 'monban/providers/oauth2/client';
```

## `new OAuth2Client()`

Creates an OAuth2 client instance.

```typescript
const providerClient = new OAuth2Client();
```

## `signIn`

Signs in with OAuth2.

```typescript
await monbanClient.signIn.provider(redirectUrl);
```

### `redirectUrl?: string`

default: `undefined`

The redirect URL.
If undefined is set, it will redirect to the current URL.
