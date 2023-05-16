export type RemoveUndefined<T> = T extends undefined ? never : T;
export type KeyOfSpecificTypeValue<T, U> = RemoveUndefined<{
    [K in keyof T]: T[K] extends U ? K : undefined;
}[keyof T]>;
export type OmitBySpecificTypeValue<T, U> = Omit<T, KeyOfSpecificTypeValue<T, U>>;
