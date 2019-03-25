'use strict'
const bls = require('./bls.js')
const assert = require('assert')
const { performance } = require('perf_hooks')

const curveTest = (curveType, name) => {
  bls.init(curveType)
    .then(() => {
      try {
        console.log(`name=${name} curve order=${bls.getCurveOrder()}`)
        serializeTest()
        signatureTest()
        miscTest()
        shareTest()
        addTest()
        console.log('all ok')
        benchAll()
      } catch (e) {
        console.log(`TEST FAIL ${e}`)
        assert(false)
      }
    })
}

async function curveTestAll () {
  // can't parallel
  await curveTest(bls.BN254, 'BN254')
  await curveTest(bls.BN381_1, 'BN381_1')
  await curveTest(bls.BLS12_381, 'BLS12_381')
}

curveTestAll()

function serializeSubTest (t, Cstr) {
  const s = t.serializeToHexStr()
  const t2 = new Cstr()
  t2.deserializeHexStr(s)
  assert.deepEqual(t.serialize(), t2.serialize())
}

function serializeTest () {
  const sec = new bls.SecretKey()
  sec.setByCSPRNG()
  serializeSubTest(sec, bls.SecretKey)
  const pub = sec.getPublicKey()
  serializeSubTest(pub, bls.PublicKey)
  const msg = 'abc'
  const sig = sec.sign(msg)
  serializeSubTest(sig, bls.Signature)
  const id = new bls.Id()
  id.setStr('12345')
  serializeSubTest(id, bls.Id)
}

function signatureTest () {
  const sec = new bls.SecretKey()

  sec.setByCSPRNG()
  sec.dump('secretKey ')

  const pub = sec.getPublicKey()
  pub.dump('publicKey ')

  const msg = 'doremifa'
  console.log('msg ' + msg)
  const sig = sec.sign(msg)
  sig.dump('signature ')

  assert(pub.verify(sig, msg))
}

function bench (label, count, func) {
  const start = performance.now()
  for (let i = 0; i < count; i++) {
    func()
  }
  const end = performance.now()
  const t = (end - start) / count
  const roundTime = (Math.round(t * 1000)) / 1000
  console.log(label + ' ' + roundTime)
}

function benchBls () {
  const msg = 'hello wasm'
  const sec = new bls.SecretKey()
  sec.setByCSPRNG()
  const pub = sec.getPublicKey()
  bench('time_sign_class', 50, () => sec.sign(msg))
  const sig = sec.sign(msg)
  bench('time_verify_class', 50, () => pub.verify(sig, msg))
}

function benchAll () {
  benchBls()
}

/*
  return [min, max)
  assume min < max
*/
function randRange (min, max) {
  return min + Math.floor(Math.random() * (max - min))
}

/*
  select k of [0, n)
  @note not uniformal distribution
*/
function randSelect (k, n) {
  let a = []
  let prev = -1
  for (let i = 0; i < k; i++) {
    const v = randRange(prev + 1, n - (k - i) + 1)
    a.push(v)
    prev = v
  }
  return a
}

function miscTest () {
  const idDec = '65535'
  const id = new bls.Id()
  id.setStr(idDec)
  assert(id.getStr(), '65535')
  assert(id.getStr(16), 'ffff')
}

function shareTest () {
  const k = 4
  const n = 10
  const msg = 'this is a pen'
  const msk = []
  const mpk = []
  const idVec = []
  const secVec = []
  const pubVec = []
  const sigVec = []

  /*
    setup master secret key
  */
  for (let i = 0; i < k; i++) {
    const sk = new bls.SecretKey()
    sk.setByCSPRNG()
    msk.push(sk)

    const pk = sk.getPublicKey()
    mpk.push(pk)
  }
  const secStr = msk[0].serializeToHexStr()
  const pubStr = mpk[0].serializeToHexStr()
  const sigStr = msk[0].sign(msg).serializeToHexStr()
  assert(mpk[0].verify(msk[0].sign(msg), msg))

  /*
    key sharing
  */
  for (let i = 0; i < n; i++) {
    const id = new bls.Id()
//    blsIdSetInt(id, i + 1)
    id.setByCSPRNG()
    idVec.push(id)
    const sk = new bls.SecretKey()
    sk.share(msk, idVec[i])
    secVec.push(sk)

    const pk = new bls.PublicKey()
    pk.share(mpk, idVec[i])
    pubVec.push(pk)

    const sig = sk.sign(msg)
    sigVec.push(sig)
  }

  /*
    recover
  */
  const idxVec = randSelect(k, n)
  console.log('idxVec=' + idxVec)
  let subIdVec = []
  let subSecVec = []
  let subPubVec = []
  let subSigVec = []
  for (let i = 0; i < idxVec.length; i++) {
    let idx = idxVec[i]
    subIdVec.push(idVec[idx])
    subSecVec.push(secVec[idx])
    subPubVec.push(pubVec[idx])
    subSigVec.push(sigVec[idx])
  }
  {
    const sec = new bls.SecretKey()
    const pub = new bls.PublicKey()
    const sig = new bls.Signature()

    sec.recover(subSecVec, subIdVec)
    pub.recover(subPubVec, subIdVec)
    sig.recover(subSigVec, subIdVec)
    assert(sec.serializeToHexStr(), secStr)
    assert(pub.serializeToHexStr(), pubStr)
    assert(sig.serializeToHexStr(), sigStr)
  }
}

function addTest () {
  const n = 5
  const m = "abc"
  const sec = []
  const pub = []
  const sig = []
  for (let i = 0; i < n; i++) {
    sec.push(new bls.SecretKey())
    sec[i].setByCSPRNG()
    pub.push(sec[i].getPublicKey())
    sig.push(sec[i].sign(m))
    assert(pub[i].verify(sig[i], m))
  }
  for (let i = 1; i < n; i++) {
    sec[0].add(sec[i])
    pub[0].add(pub[i])
    sig[0].add(sig[i])
  }
  assert(pub[0].verify(sig[0], m))
  const sig2 = sec[0].sign(m)
  assert(sig2.isEqual(sig[0]))
}
