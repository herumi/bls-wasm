const mcl = require("./mcl-wasm/mcl.js");
const bls = require("./bls-eth-wasm/bls.js");

/**
 * VerifyMultipleSignatures verifies a non-singular set of signatures and its respective pubkeys and messages.
 * This method provides a safe way to verify multiple signatures at once. We pick a number randomly from 1 to max
 * uint64 and then multiply the signature by it. We continue doing this for all signatures and its respective pubkeys.
 * S* = S_1 * r_1 + S_2 * r_2 + ... + S_n * r_n
 * P'_{i,j} = P_{i,j} * r_i
 * e(S*, G) = \prod_{i=1}^n \prod_{j=1}^{m_i} e(P'_{i,j}, M_{i,j})
 * Using this we can verify multiple signatures safely.
 *
 * Implements: https://ethresear.ch/t/fast-verification-of-multiple-bls-signatures/5407
 * Based on:   https://github.com/prysmaticlabs/prysm/blob/00d5cd551f1a1a66ce0012e5bd88f750023c0136/shared/bls/herumi/signature.go#L154
 */
function verifyMultipleSignatures(sigVec, pubVec, msgVec) {
  // Concat msgVec into a single Uint8Array
  const msgsConcat = concatUint8Array(msgVec);

  // Get and cast random values to Fr
  const randXs = Array.from({ length: sigVec.length }, (_, i) => {
    const x = new mcl.Fr();
    // mcl.Fr.setLittleEndian(bytesutil.Bytes8(rNum));
    x.setByCSPRNG();
    return x;
  });

  // Cast signatures to G2 values
  const sigVecG2s = sigVec.map(castSigToG2);
  // Multi scalar multiplication on: Sig * rand, as G2 points
  const finalSig = mcl.mulVec(sigVecG2s, randXs);
  const aggSig = new bls.Signature();
  aggSig.deserialize(finalSig.serialize());

  // Scalar multiplication on: Pub * rand, as G1 points
  const multiKeys = pubVec.map((pub, i) =>
    castG1ToPub(mcl.mul(castPubToG1(pub), randXs[i]))
  );

  return aggSig.aggregateVerifyNoCheck(multiKeys, msgsConcat);
}

function castSigToG2(sig) {
  const g2 = new mcl.G2();
  g2.deserialize(sig.serialize());
  return g2;
}

function castG2ToSig(g2) {
  const sig = new bls.Signature();
  sig.deserialize(g2.serialize());
  return sig;
}

function castPubToG1(pub) {
  const g1 = new mcl.G1();
  g1.deserialize(pub.serialize());
  return g1;
}

function castG1ToPub(g1) {
  const pub = new bls.PublicKey();
  pub.deserialize(g1.serialize());
  return pub;
}

function concatUint8Array(msgVec) {
  let currentLen = 0;
  const totalLen = msgVec.reduce((len, msg) => len + msg.length, 0);
  return msgVec.reduce((msgs, msg) => {
    msgs.set(msg, currentLen);
    currentLen += msg.length;
    return msgs;
  }, new Uint8Array(totalLen));
}

module.exports = {
  verifyMultipleSignatures,
  castSigToG2,
  castG2ToSig,
  castPubToG1,
  castG1ToPub,
  concatUint8Array,
};
