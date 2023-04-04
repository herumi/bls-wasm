'use strict'
const bls = require('../src/index.js')
const assert = require('assert')
const { performance } = require('perf_hooks')

const curveTest = (curveType, name) => {
  bls.init(curveType)
    .then(() => {
      try {
        console.log(`name=${name} curve order=${bls.getCurveOrder()}`)
        dfinityTest()
        console.log('all ok')
      } catch (e) {
        console.log(`TEST FAIL ${e}`)
        assert(false)
      }
    })
}

async function curveTestAll () {
  await curveTest(bls.BLS12_381, 'BLS12_381')
}

curveTestAll()

function dfinityTest () {
  // set Ethereum serialization format.
  bls.setETHserialiation(true)
  bls.setMapToMode(bls.MAP_TO_MODE_HASH_TO_CURVE)
  const gen = new bls.PublicKey()
  gen.setStr('1 0x24aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8 0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e 0xce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801 0x606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be', 16)
  bls.setGeneratorOfPublicKey(gen)

  bls.setDstG1('BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_')
  // end of init

  // test of https://github.com/dfinity/agent-js/blob/5214dc1fc4b9b41f023a88b1228f04d2f2536987/packages/bls-verify/src/index.test.ts#L101
  let pub = new bls.PublicKey()
  let sig = new bls.Signature()
  pub.deserializeHexStr('a7623a93cdb56c4d23d99c14216afaab3dfd6d4f9eb3db23d038280b6d5cb2caaee2a19dd92c9df7001dede23bf036bc0f33982dfb41e8fa9b8e96b5dc3e83d55ca4dd146c7eb2e8b6859cb5a5db815db86810b8d12cee1588b5dbf34a4dc9a5')
  sig.deserializeHexStr('b89e13a212c830586eaa9ad53946cd968718ebecc27eda849d9232673dcd4f440e8b5df39bf14a88048c15e16cbcaabe')

  assert(pub.verify(sig, "hello"))
  assert(!pub.verify(sig, "hallo"))
}

