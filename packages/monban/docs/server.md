# `Monban`

## `new Monban(providers, options)`

Creates a new Monban instance.

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

## `getSession(request)`

Gets a session from a request.

## `createSessionCookie(session)`

Creates a session cookie.

## `createSession(profile)`

Creates a session.

## `verifySession(session)`

Verifies a session.

## `extendSession(session)`

Extends a session.

## `invalidateSession(sessionId)`

Invalidates a session.

## `invalidateUserSessions(userId)`

Invalidates all sessions of a user.

## `encodeToken(session)`

Encodes a session into a JWT.

## `decodeToken(token)`

Decodes and verifies a JWT.

## `createCsrfToken()`

Creates a CSRF token and a cookie.
