interface Common {
    constructor(size: number);

    deserializeHexStr(s: string): void;

    serializeToHexStr(): string;

    dump(msg?: string): string;

    clear(): void;

    isEqual(rhs: this): boolean

    deserialize(v: Uint8Array): void;

    serialize(): Uint8Array;

    add(rhs: this): void;
}

interface SecretKey extends Common {

    constructor();

    setInt(x: number): void;

    setHashOf(a: Uint8Array): void;

    setLittleEndian(a: Uint8Array): void;

    setByCSPRNG(): void;

    getPublicKey(): PublicKey;

    sign(m: string | Uint8Array): Signature;

    /**
     *
     * @param m must have 40 bytes
     */
    signHashWithDomain(m: Uint8Array): Signature;
}

interface PublicKey extends Common {
    constructor();

    verify(signature: Signature, m: Uint8Array | string): boolean;

    /**
     *
     * @param signature
     * @param m must have 40 bytes
     */
    verifyHashWithDomain(signature: Signature, m: Uint8Array): boolean;
}

interface Signature extends Common {

    /**
     *
     * @param publicKeys
     * @param messages each message must have 40bytes
     */
    verifyAggregatedHashWithDomain(publicKeys: PublicKey[], messages: Uint8Array[]): boolean

}

export interface BlsWasmWrapper {

    init(): Promise<void>;

    toHex(array: Uint8Array, start: number, end: number): string;

    toHexStr(array: Uint8Array): string;

    fromHexStr(s: string): Uint8Array;

    getCurveOrder(): number;

    getFieldOrder(): number;

    deserializeHexStrToSecretKey(s: string): SecretKey;

    deserializeHexStrToPublicKey(s: string): PublicKey;

    deserializeHexStrToSignature(s: string): Signature;

    SecretKey: SecretKey;
    PublicKey: PublicKey;

}