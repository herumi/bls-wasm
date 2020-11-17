'use strict'
const bls = require('../src/index.js')
const assert = require('assert')

const curveTest = (curveType, name) => {
  bls.init(curveType)
    .then(() => {
      try {
        console.log(`name=${name}`)
        FrTest()
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

function FrTest () {
  const a = new bls.Fr()
  a.setInt(5)
  assert.equal(a.getStr(), '5')
  a.setStr('65535')
  assert.equal(a.getStr(), '65535')
  assert.equal(a.getStr(16), 'ffff')
  a.setStr('ff', 16)
  assert.equal(a.getStr(), '255')
  a.setStr('0x10')
  assert.equal(a.getStr(), '16')
  assert.equal(a.getStr(16), '10')
  const b = new bls.Fr()
  a.setByCSPRNG()
  b.deserialize(a.serialize())
  assert.deepEqual(a.serialize(), b.serialize())
  a.setStr('1000000000020')
  b.setInt(-15)
  assert.equal(bls.add(a, b).getStr(), '1000000000005')
  assert.equal(bls.sub(a, b).getStr(), '1000000000035')
  a.setInt(200)
  b.setInt(20)
  assert.equal(bls.mul(a, b).getStr(), '4000')
  assert.equal(bls.div(a, b).getStr(), '10')
  assert.equal(bls.mul(bls.div(b, a), a).getStr(), '20')
  a.setInt(-123)
  assert.equal(bls.neg(a).getStr(), '123')
  assert.equal(bls.mul(a, bls.inv(a)).getStr(), '1')
  a.setInt(123459)
  assert(bls.mul(a, a).isEqual(bls.sqr(a)))

  a.setInt(3)
  assert(!a.isZero())
  assert(!a.isOne())
  a.setInt(1)
  assert(!a.isZero())
  assert(a.isOne())
  a.setInt(0)
  assert(a.isZero())
  assert(!a.isOne())
  a.setInt(5)
  b.setInt(3)
  assert(!a.isEqual(b))
  b.setInt(5)
  assert(a.isEqual(b))

  a.setHashOf('abc')
  a.dump()
  b.setHashOf([97, 98, 99])
  assert(a.isEqual(b))

  b.clear()
  b.deserialize(a.serialize())
  assert(a.isEqual(b))
  a.setLittleEndianMod(new Uint8Array([1, 2, 3]))
  b.setInt(1 + 256 * (2 + 256 * 3))
  assert(a.isEqual(b))
  a.clear()
  a.setLittleEndian(new Uint8Array([1, 2, 3]))
  assert(a.isEqual(b))
  a.clear()
  a.setBigEndianMod(new Uint8Array([3, 2, 1]))
  assert(a.isEqual(b))
  a.setByCSPRNG()
  console.log(`rand ${a.getStr(16)}`)
}
