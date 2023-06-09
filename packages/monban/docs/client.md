# `MonbanClient`

## `new MonbanClient(endpoint, providerClients)`

Creates a Monban client.

```typescript
const providerClients = {
    google: new GoogleClient(),
};

const monbanClient = new MonbanClient<User, typeof providerClients>('/monban', providerClients);
```

### `endpoint`

The endpoint of the server.

### `providerClients`

An object of provider clients.

-   [JsonProvider](/packages/monban/src/providers/json/)
-   [OAuth2Provider](/packages/monban/src/providers/oauth2/)
-   [GoogleProvider](/packages/monban/src/providers/google/)

## `signIn.{provider}(options)`

Signs in with a provider.

```typescript
await monbanClient.signIn.google();
```

## `signOut()`

Signs out.

```typescript
await monbanClient.signOut();
```

## `onSessionChange(callback)`

Registers a callback to be called when the session changes.

```typescript
const unsubscribe: () => void = monbanClient.onSessionChange((session) => {
    console.log(session);
});
```

## `getSession()`

Gets the current session.

```typescript
const session: Session<User> | undefined = await monbanClient.getSession();
```

## `getCsrfToken()`

Gets the CSRF token.

To fetch endpoints that require a session using HTTP methods other than GET, the CSRF token must be set in the `x-monban-csrf-token` header.

```typescript
const csrfToken: string = await monbanClient.getCsrfToken();

await fetch(`/articles`, {
    method: 'post',
    headers: {
        'content-type': 'application/json',
        'x-monban-csrf-token': csrfToken,
    },
    body: JSON.stringify({
        title: 'Hello, world!',
        body: '...',
    }),
});
```
