# `MonbanClient`

## `new MonbanClient(endpoint, providerClients)`

Creates a Monban client.

### `endpoint`

The endpoint of the server.

### `providerClients`

An object of provider clients.

-   [JsonProvider](/packages/monban/src/providers/json/)
-   [OAuth2Provider](/packages/monban/src/providers/oauth2/)
-   [GoogleProvider](/packages/monban/src/providers/google/)

## `signIn.{provider}(options)`

Signs in with a provider.

## `signOut()`

Signs out.

## `onSessionChange(callback)`

Registers a callback to be called when the session changes.

## `getSession()`

Gets the current session.

## `getCsrfToken()`

Gets the CSRF token.
