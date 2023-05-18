import * as cookie from 'cookie';
import { Monban, Provider } from '../src/main';

describe('Monban', () => {
    type TestUser = { id: string };
    type TestProfile = { provider: string };
    const options = { secret: 'secret' };

    describe('isAuthenticated', () => {
        test('should return undefined if token is not present', async () => {
            const providers = {};
            const monban = new Monban<TestUser, typeof providers>(providers, options);

            const req = new Request('https://example.com');

            const result = await monban.isAuthenticated(req);
            expect(result).toBeUndefined();
        });

        test('should return undefined if token is invalid', async () => {
            const providers = {};
            const monban = new Monban<TestUser, typeof providers>(providers, options);
            const anotherMonban = new Monban<TestUser, typeof providers>(providers, { secret: 'another secret' });

            const token = anotherMonban.encodeToken({ sub: 'test', user: { id: 'test' } });
            const req = new Request('https://example.com', {
                headers: new Headers({
                    cookie: cookie.serialize('_monban_token', token),
                }),
            });

            const result = await monban.isAuthenticated(req);
            expect(result).toBeUndefined();
        });

        test('should return undefined if csrf token is not valid and request method is not GET', async () => {
            const providers = {};
            const monban = new Monban<TestUser, typeof providers>(providers, options);

            const token = monban.encodeToken({ sub: 'test', user: { id: 'test' } });
            const req = new Request('https://example.com', {
                method: 'POST',
                headers: new Headers({
                    cookie: `${cookie.serialize('_monban_token', token)}; ${cookie.serialize(
                        '_monban_csrf_token',
                        'invalid',
                    )}`,
                    'x-monban-csrf-token': 'valid',
                }),
            });

            const result = await monban.isAuthenticated(req);
            expect(result).toBeUndefined();
        });

        test('should return the payload if token and csrf token are valid', async () => {
            const providers = {};
            const monban = new Monban<TestUser, typeof providers>(providers, options);

            const payload = { sub: 'test', user: { id: 'test' } };
            const token = monban.encodeToken(payload);
            const req = new Request('https://example.com', {
                headers: new Headers({
                    cookie: `${cookie.serialize('_monban_token', token)}; ${cookie.serialize(
                        '_monban_csrf_token',
                        'valid',
                    )}`,
                    'x-monban-csrf-token': 'valid',
                }),
            });

            const result = await monban.isAuthenticated(req);
            expect(result).toEqual(expect.objectContaining(payload));
        });
    });

    describe('handleRequest', () => {
        test('should return provider response for /providers/:provider path', async () => {
            const mockProvider = {
                handleRequest: jest.fn().mockResolvedValue(new Response('Provider response')),
            } as unknown as Provider<TestProfile>;

            const providers = { mock: mockProvider };
            const monban = new Monban<TestUser, typeof providers>(providers, options);

            const req = new Request('https://example.com/providers/mock');
            const res = await monban.handleRequest(req, '/');

            expect(mockProvider.handleRequest).toHaveBeenCalled();
            expect(await res.text()).toEqual('Provider response');
        });

        test('should return 404 for non-existent provider', async () => {
            const providers = {};
            const monban = new Monban<TestUser, typeof providers>(providers, options);

            const req = new Request('https://example.com/providers/nonexistent');
            const res = await monban.handleRequest(req, '/');

            expect(res.status).toEqual(404);
        });

        test('should set cookie and return empty response for /signout path', async () => {
            const providers = {};
            const monban = new Monban<TestUser, typeof providers>(providers, options);
            const req = new Request('https://example.com/signout');

            monban.isAuthenticated = jest.fn().mockResolvedValue({ sub: 'test', user: { id: 'test' } });

            const res = await monban.handleRequest(req, '/');

            const setCookieHeader = res.headers.get('set-cookie');
            const cookies = cookie.parse(setCookieHeader ?? '');
            expect(cookies._monban_token).toEqual('');
            expect(await res.text()).toEqual('');
        });

        test('should return user payload for /session path if authenticated', async () => {
            const providers = {};
            const monban = new Monban<TestUser, typeof providers>(providers, options);

            const payload = { sub: 'test', user: { id: 'test' } };
            const token = monban.encodeToken(payload);
            const req = new Request('https://example.com/session', {
                headers: new Headers({
                    cookie: cookie.serialize('_monban_token', token),
                    'x-monban-csrf-token': 'valid',
                }),
            });
            const res = await monban.handleRequest(req, '/');

            expect(await res.json()).toEqual(payload);
        });

        test('should return 401 status for /session path if not authenticated', async () => {
            const providers = {};
            const monban = new Monban<TestUser, typeof providers>(providers, options);

            const req = new Request('https://example.com/session');
            const res = await monban.handleRequest(req, '/');

            expect(res.status).toEqual(401);
            expect(await res.text()).toEqual('');
        });

        test('should return csrf token for /csrf path if authenticated', async () => {
            const providers = {};
            const monban = new Monban<TestUser, typeof providers>(providers, options);

            const req = new Request('https://example.com/csrf');
            const res = await monban.handleRequest(req, '/');

            const setCookieHeader = res.headers.get('set-cookie');
            const cookies = cookie.parse(setCookieHeader ?? '');
            expect(cookies._monban_csrf_token).toBeDefined();
            expect(await res.json()).toEqual({ token: cookies._monban_csrf_token });
        });
    });
});
