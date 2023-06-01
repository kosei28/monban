import { MonbanClient, ProviderClient, type OnSessionChangeCallback } from '../src/client';

class MockProviderClient extends ProviderClient {
    async signUp() {
        return true;
    }

    async signIn() {
        return true;
    }
}

describe('MonbanClient', () => {
    const providerClients = {
        mock: new MockProviderClient(),
    };
    let monbanClient: MonbanClient<typeof providerClients>;
    let callback: OnSessionChangeCallback;

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

    describe('signUp', () => {
        test('should call signUp method of provider client and triggerOnSessionChange', async () => {
            const result = await monbanClient.signUp.mock();

            expect(result).toEqual(true);
            expect(callback).toHaveBeenCalledTimes(2);
        });

        test('should throw error for non-existent provider client', async () => {
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            expect(() => (monbanClient.signUp as any).nonExistentProvider()).toThrow();
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
