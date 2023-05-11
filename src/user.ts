export abstract class UserManager<T> {
    abstract createUser(accountInfo: T): Promise<string>;
    abstract getUser(userId: string): Promise<object | undefined>;
    abstract deleteUser(userId: string): Promise<void>;
}
