declare class Common {

    constructor(size: number);

    deserializeHexStr(s: string): void;

    serializeToHexStr(): string;

    dump(msg?: string): string;

    clear(): void;

    clone(): this;

    isEqual(rhs: this): boolean

    deserialize(v: Uint8Array): void;

    serialize(): Uint8Array;

    add(rhs: this): void;
}

declare class SecretKeyType extends Common {

    constructor();

    setInt(x: number): void;

    setHashOf(a: Uint8Array): void;

    setLittleEndian(a: Uint8Array): void;

    setByCSPRNG(): void;

    getPublicKey(): PublicKeyType;

    sign(m: string | Uint8Array): SignatureType;

    /**
     *
     * @param m must have 40 bytes
     */
    signHashWithDomain(m: Uint8Array): SignatureType;
}

declare class PublicKeyType extends Common {

    constructor();

    verify(signature: SignatureType, m: Uint8Array | string): boolean;

    /**
     *
     * @param signature
     * @param m must have 40 bytes
     */
    verifyHashWithDomain(signature: SignatureType, m: Uint8Array): boolean;
}

declare class SignatureType extends Common {
    constructor();

    /**
     *
     * @param publicKeys
     * @param messages each message must have 40bytes
     */
    verifyAggregatedHashWithDomain(publicKeys: PublicKeyType[], messages: Uint8Array[]): boolean

}

export function init(): Promise<void>;

export function toHex(a: Uint8Array, start: number, length: number): string;
export function toHexStr(a: Uint8Array): string;
export function fromHexStr(s: string): Uint8Array;
export function getCurveOrder(): string;
export function getFieldOrder(): string;
export function deserializeHexStrToSecretKey(s: string): SecretKeyType;
export function deserializeHexStrToPublicKey(s: string): PublicKeyType;
export function deserializeHexStrToSignature(s: string): SignatureType;

export const SecretKey: typeof SecretKeyType;
export const PublicKey: typeof PublicKeyType;
export const Signature: typeof SignatureType;