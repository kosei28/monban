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
    let triggerOnSessionChange: OnSessionChangeCallback<TestUser>;

    beforeEach(async () => {
        globalThis.fetch = async () => new Response();
        globalThis.window = {
            addEventListener: jest.fn(),
        } as unknown as Window & typeof globalThis;

        monbanClient = new MonbanClient('https://example.com', providerClients);
        monbanClient.getCsrfToken = jest.fn().mockResolvedValue('csrf_token');
        triggerOnSessionChange = jest.fn();
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (monbanClient as any).triggerOnSessionChange = triggerOnSessionChange;
    });

    describe('onSessionChange', () => {
        test('should trigger callback', () => {
            const callback = jest.fn();
            monbanClient.onSessionChange(callback);

            expect(triggerOnSessionChange).toHaveBeenCalledTimes(1);
        });

        test('should remove callback when unsubscribe is called', () => {
            const callback = jest.fn();
            const unsubscribe = monbanClient.onSessionChange(callback);

            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            expect((monbanClient as any).onSessionChangeCallbacks.length).toEqual(1);

            unsubscribe();

            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            expect((monbanClient as any).onSessionChangeCallbacks.length).toEqual(0);
        });
    });

    describe('signIn', () => {
        test('should call signIn method of provider client and triggerOnSessionChange', async () => {
            const result = await monbanClient.signIn.mock();

            expect(result).toEqual(true);
            expect(triggerOnSessionChange).toHaveBeenCalledTimes(1);
        });

        test('should throw error for non-existent provider client', async () => {
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            expect(() => (monbanClient.signIn as any).nonExistentProvider()).toThrow();
        });
    });

    describe('signOut', () => {
        test('should call triggerOnSessionChange', async () => {
            await monbanClient.signOut();

            expect(triggerOnSessionChange).toHaveBeenCalledTimes(1);
        });
    });
});
