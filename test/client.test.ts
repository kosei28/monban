import { MonbanClient, ProviderClient, type OnSessionChangeCallback } from '../src/client';

class MockProviderClient extends ProviderClient {
    async signIn() {
        return true;
    }
}

describe('MonbanClient', () => {
    type TestUser = {
        id: string;
    };

    const providerClients = {
        mock: new MockProviderClient(),
    };
    let monbanClient: MonbanClient<TestUser, typeof providerClients>;
    let callback: OnSessionChangeCallback<TestUser>;

    globalThis.fetch = async () => new Response();

    beforeEach(async () => {
        monbanClient = new MonbanClient('https://example.com', providerClients);
        monbanClient.getCsrfToken = jest.fn().mockResolvedValue('csrf_token');
        callback = jest.fn();
        await monbanClient.onSessionChange(callback);
    });

    describe('onSessionChange', () => {
        test('should triggers callback', () => {
            expect(callback).toHaveBeenCalledTimes(1);
        });
    });

    describe('signIn', () => {
        test('should call signIn method of provider client and triggerOnSessionChange', async () => {
            const result = await monbanClient.signIn.mock();

            expect(result).toEqual(true);
            expect(callback).toHaveBeenCalledTimes(2);
        });

        test('should throw error for non-existent provider client', async () => {
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            expect(() => (monbanClient.signIn as any).nonExistentProvider()).toThrow();
        });
    });

    describe('signOut', () => {
        test('should call triggerOnSessionChange', async () => {
            await monbanClient.signOut();

            expect(callback).toHaveBeenCalledTimes(2);
        });
    });
});
