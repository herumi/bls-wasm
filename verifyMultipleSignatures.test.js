const assert = require("assert");
const mcl = require("./mcl-wasm/mcl.js");
const bls = require("./bls-eth-wasm/bls.js");
const {
  verifyMultipleSignatures,
  castSigToG2,
  castG2ToSig,
  concatUint8Array,
} = require("./verifyMultipleSignatures");

mcl
  .init(mcl.BLS12_381)
  .then(() => {
    // Configure mcl for eth2.0 specs
    mcl.setETHserialization(true);
    mcl.setMapToMode(mcl.IRTF);
  })
  .then(() => bls.init(bls.BLS12_381))
  .then(() => {
    testMultipleSignatureVerification();
    testMultipleSignatureVerification_FailsCorrectly();
    console.log("Test passed");
  });

/**
 * Test successful case
 */
function testMultipleSignatureVerification() {
  const { sigVec, pubVec, msgVec } = generateMockData(100, 32);

  assert(
    verifyMultipleSignatures(sigVec, pubVec, msgVec),
    "Signature did not verify"
  );
}

/**
 * Test case with maliciously crafted signatures to fool aggregateVerifyNoCheck
 */
function testMultipleSignatureVerification_FailsCorrectly() {
  const { sigVec, pubVec, msgVec } = generateMockData(100, 32);

  // We mess with the last 2 signatures, where we modify their values
  // such that they wqould not fail in aggregate signature verification.
  const lastSig = sigVec[sigVec.length - 1];
  const secondLastSig = sigVec[sigVec.length - 2];
  // Convert to bls object
  const rawSig = new bls.Signature();
  rawSig.deserialize(secondLastSig.serialize());

  const rawSig2 = new bls.Signature();
  rawSig2.deserialize(lastSig.serialize());

  // set random field prime value
  const fprime = new mcl.Fp();
  fprime.setInt(100);

  // set random field prime value.
  const fprime2 = new mcl.Fp();
  fprime2.setInt(50);

  // make a combined fp2 object.
  const fp2 = new mcl.Fp2();
  fp2.D = [fprime, fprime2];

  const g2Point = fp2.mapToG2();

  // We now add/subtract the respective g2 points by a fixed
  // value. This would cause singluar verification to fail but
  // not aggregate verification.
  let firstG2 = castSigToG2(rawSig);
  let secondG2 = castSigToG2(rawSig2);
  firstG2 = mcl.add(firstG2, g2Point);
  secondG2 = mcl.sub(secondG2, g2Point);
  sigVec[sigVec.length - 1] = castG2ToSig(firstG2);
  sigVec[sigVec.length - 2] = castG2ToSig(secondG2);

  // This method is expected to pass, as it would not
  // be able to detect bad signatures
  const aggSig = new bls.Signature();
  aggSig.aggregate(sigVec);
  assert(
    aggSig.aggregateVerifyNoCheck(pubVec, concatUint8Array(msgVec)),
    "Signature did not verify"
  );

  // This method would be expected to fail.
  assert(
    !verifyMultipleSignatures(sigVec, pubVec, msgVec),
    "Signature verified when it was not supposed to"
  );
}

function generateMockData(n, msgSize) {
  const sigVec = [];
  const pubVec = [];
  const msgVec = [];

  for (let i = 0; i < n; i++) {
    const secKey = new bls.SecretKey();
    secKey.setByCSPRNG();
    const pubKey = secKey.getPublicKey();
    const msg = new Uint8Array(msgSize);
    msg[0] = i; // Make each message different
    const sig = secKey.sign(msg);

    // Sanity check, each sig should be valid individually
    assert(pubKey.verify(sig, msg));

    sigVec.push(sig);
    pubVec.push(pubKey);
    msgVec.push(msg);
  }

  // Sanity check to make sure messages are different
  assert(bls.areAllMsgDifferent(concatUint8Array(msgVec), msgSize));

  return {
    sigVec,
    pubVec,
    msgVec,
  };
}
