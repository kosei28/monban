# `Monban`

```typescript
import { Monban } from 'monban';
```

## `new Monban(providers, options)`

Creates a Monban instance.

```typescript
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
```

### `providers`

An object of provider instances.

-   [JsonProvider](/packages/monban/src/providers/json/)
-   [OAuth2Provider](/packages/monban/src/providers/oauth2/)
-   [GoogleProvider](/packages/monban/src/providers/google/)

### `options`

#### `secret: string`

A secret string used to sign JWT.

#### `maxAge?: number`

default: `3600`

The maximum age of the session in seconds.

#### `csrf?: boolean`

default: `true`

Whether to use CSRF protection or not.

#### `cookie?: cookie.CookieSerializeOptions`

default:

```typescript
{
    path: '/',
    sameSite: 'lax',
    secure: true,
    httpOnly: true,
};
```

[Cookie options.](https://github.com/jshttp/cookie#options-1)

> **Note**
>
> If maxAge is set in the cookie option, it is overridden by the value of the maxAge option.

#### `adapter?: Adapter`

default: `undefined`

An adapter to store sessions.

-   [RedisAdapter](/packages/redis-adapter/)
-   [UpstashRedisAdapter](/packages/upstash-redis-adapter/)

> **Warning**
>
> If you don't specify an adapter, sessions cannot be invalidated. This is not recommended for production.

#### `callbacks`

##### `getUser: (profile) => Promise<User | undefined>`

A callback that returns user data to include in the session.
You can create and retrieve users in any database in this callback, based on the authentication profile given in the argument.
If undefined is returned, the session will not be created and the login will fail.

## `handleRequest(request, endpoint)`

Handles a request.

```typescript
const response: Response = await monban.handleRequest(request, '/monban');
```

## `getSession(request)`

Gets a session from a request.

```typescript
const session: Session<User> | undefined = await monban.getSession(request);
```

## `createSessionCookie(session)`

Creates a session cookie.

```typescript
const setCookie: string = await monban.createSessionCookie(session);
```

## `createSession(profile)`

Creates a session.

```typescript
const session: Session<User> | undefined = await monban.createSession(profile);
```

## `verifySession(session)`

Verifies a session.

```typescript
const isValid: boolean = await monban.verifySession(session);
```

## `extendSession(session)`

Extends a session.

```typescript
await monban.extendSession(session);
```

## `invalidateSession(sessionId)`

Invalidates a session.

```typescript
await monban.invalidateSession(sessionId);
```

## `invalidateUserSessions(userId)`

Invalidates all sessions of a user.

```typescript
await monban.invalidateUserSessions(userId);
```

## `encodeToken(session)`

Encodes a session into a JWT.

```typescript
const token: string = await monban.encodeToken(session);
```

## `decodeToken(token)`

Decodes and verifies a JWT.

```typescript
const payload: TokenPayload<User> | undefined = await monban.decodeToken(token);
```

## `createCsrfToken()`

Creates a CSRF token and a cookie.

```typescript
const { token, setCookie }: { token: string; setCookie: string } = monban.createCsrfToken();
```
