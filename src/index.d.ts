declare class Common {
  constructor(size: number);

  deserializeHexStr(s: string): void;
  serializeToHexStr(): string;
  dump(msg?: string): void;
  clear(): void;
  clone(): this;
  isEqual(rhs: this): boolean
  deserialize(v: Uint8Array): void;
  serialize(): Uint8Array;
  add(rhs: this): void;
}

declare class Fr extends Common {
  constructor();

  setInt(x: number): void;
  deserialize(s: Uint8Array): void;
  serialize(): Uint8Array;
  setStr(s: string): void;
  getStr(): string;
  isZero(): boolean;
  isOne(): boolean;
  isEqual(rhs: this): boolean;
  setLittleEndian(a: Uint8Array): void;
  setLittleEndianMod(a: Uint8Array): void;
  setByCSPRNG(): void;
  setHashOf(a: Uint8Array): void;
}

declare class Id extends Common {
  constructor();

  setInt(x: number): void;
  isEqual(rhs: this): boolean;
  deserialize(s: Uint8Array): void;
  serialize(): Uint8Array;
  setStr(s: string): void;
  getStr(): string;
  setLittleEndian(a: Uint8Array): void;
  setLittleEndianMod(a: Uint8Array): void;
  setByCSPRNG(): void;
}

declare class SecretKeyType extends Common {
  constructor();

  setInt(x: number): void;
  isZero(): boolean;
  isEqual(rhs: this): boolean;
  deserialize(s: Uint8Array): void;
  serialize(): Uint8Array;
  add(rhs: this): void;
  share(msk: SecretKeyType[], id: Id): void;
  recover(setVec: any, idVec: any): void;
  setHashOf(a: Uint8Array): void;
  setLittleEndian(a: Uint8Array): void;
  setLittleEndianMod(a: Uint8Array): void;
  setByCSPRNG(): void;
  getPublicKey(): PublicKeyType;
  sign(m: string | Uint8Array): SignatureType;
}

declare class PublicKeyType extends Common {
  constructor();

  isZero(): boolean;
  isEqual(rhs: this): boolean;
  deserialize(s: Uint8Array): void;
  serialize(): Uint8Array;
  deserializeUncompressed (s: Uint8Array): void;
  serializeUncompressed (): Uint8Array;
  add(rhs: this): void;
  share(mpk: PublicKeyType[], id: Id): void;
  recover(secVec: PublicKeyType[], idVec: Id[]): void;
  isValidOrder(): boolean;
  verify(signature: SignatureType, m: Uint8Array | string): boolean;
}

declare class SignatureType extends Common {
  constructor();

  isZero(): boolean;
  isEqual(rhs: this): boolean;
  deserialize(s: Uint8Array): void;
  serialize(): Uint8Array;
  deserializeUncompressed (s: Uint8Array): void;
  serializeUncompressed (): Uint8Array;
  add(rhs: this): void;
  recover(secVec: SignatureType[], idVec: Id[]): void;
  isValidOrder(): boolean;
  aggregate(others: SignatureType[]): boolean;
  fastAggregateVerify(publicKeys: PublicKeyType[], message: Uint8Array): boolean;
  aggregateVerifyNoCheck(publicKeys: PublicKeyType[], messages: Uint8Array): boolean;
}

export function init(curveType: CurveType): Promise<void>;
export function blsInit(curveType: CurveType): void;

export function toHex(a: Uint8Array, start: number, length: number): string;
export function toHexStr(a: Uint8Array): string;
export function fromHexStr(s: string): Uint8Array;
export function deserializeHexStrToSecretKey(s: string): SecretKeyType;
export function deserializeHexStrToPublicKey(s: string): PublicKeyType;
export function deserializeHexStrToSignature(s: string): SignatureType;

export function getCurveOrder(): string;
export function getFieldOrder(): string;
export function verifySignatureOrder(doVerify: boolean): void;
export function verifyPublicKeyOrder(doVerify: boolean): void;

/**
*
* @param msgs single array with concatenated messages
* @param msgSize defaults to MSG_SIZE
*/
export function areAllMsgDifferent(msgs: Uint8Array, msgSize?: number): boolean;

/**
* return true if all pub[i].verify(sigs[i], msgs[i])
* @param msgs msgs is a concatenation of arrays of 32-byte Uint8Array
*/
export function multiVerify(pubs: PublicKeyType[], sigs: SignatureType[], msgs: Uint8Array[]): boolean;

export const SecretKey: typeof SecretKeyType;
export const PublicKey: typeof PublicKeyType;
export const Signature: typeof SignatureType;

export enum CurveType {
  BN254 = 0,
  BLS12_381 = 5,
}

export const BN254 = CurveType.BN254;
export const BLS12_381 = CurveType.BLS12_381;
export const ethMode = true;
export const MSG_SIZE = 32;

