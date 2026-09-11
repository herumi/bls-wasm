/**
 * @param createModule Async factory that returns an emcc initialized Module
 * In node, `const createModule = require(`./bls_c.js`)`
 */
const ETH_MODE = false

const _blsSetupFactory = (createModule) => {
  const exports = {}
  /* eslint-disable */
  exports.BN254 = 0
  exports.BN381_1 = 1
  exports.BN_SNARK1 = 4
  exports.BLS12_381 = 5
  exports.ethMode = ETH_MODE
  exports.ETH_MODE_DRAFT_05 = 1
  exports.ETH_MODE_DRAFT_06 = 2
  exports.ETH_MODE_DRAFT_07 = 3
  exports.MAP_TO_MODE_ORIGINAL = 0
  exports.MAP_TO_MODE_HASH_TO_CURVE = 5 // IRTF

  function blsSetup(exports, curveType) {
    const mod = exports.mod
    const MCLBN_FP_UNIT_SIZE = 6
    const MCLBN_FP_SIZE = MCLBN_FP_UNIT_SIZE * 8
    const MCLBN_FR_UNIT_SIZE = 4
    const MCLBN_FR_SIZE = MCLBN_FR_UNIT_SIZE * 8
    const BLS_COMPILER_TIME_VAR_ADJ = exports.ethMode ? 200 : 0
    const MCLBN_COMPILED_TIME_VAR = (MCLBN_FR_UNIT_SIZE * 10 + MCLBN_FP_UNIT_SIZE) + BLS_COMPILER_TIME_VAR_ADJ
    const BLS_ID_SIZE = MCLBN_FR_SIZE
    const BLS_SECRETKEY_SIZE = MCLBN_FR_SIZE
    const BLS_PUBLICKEY_SIZE = MCLBN_FP_SIZE * 3 * (exports.ethMode ? 1 : 2)
    const BLS_SIGNATURE_SIZE = MCLBN_FP_SIZE * 3 * (exports.ethMode ? 2 : 1)

    const ptrToAsciiStr = (pos, n) => {
      let s = ''
      for (let i = 0; i < n; i++) {
        s += String.fromCharCode(mod.HEAP8[pos + i])
      }
      return s
    }
    const asciiStrToPtr = (pos, s) => {
      for (let i = 0; i < s.length; i++) {
        mod.HEAP8[pos + i] = s.charCodeAt(i)
      }
    }
    exports.toHex = (a, start, n) => {
      let s = ''
      for (let i = 0; i < n; i++) {
        s += ('0' + a[start + i].toString(16)).slice(-2)
      }
      return s
    }
    // Uint8Array to hex string
    exports.toHexStr = a => {
      return exports.toHex(a, 0, a.length)
    }
    // hex string to Uint8Array
    exports.fromHexStr = s => {
      if (s.length & 1) throw new Error('fromHexStr:length must be even ' + s.length)
      const n = s.length / 2
      const a = new Uint8Array(n)
      for (let i = 0; i < n; i++) {
        a[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16)
      }
      return a
    }
///////////////////////////
    const copyToUint32Array = (a, pos) => {
      a.set(mod.HEAP32.subarray(pos / 4, pos / 4 + a.length))
//    for (let i = 0; i < a.length; i++) {
//      a[i] = mod.HEAP32[pos / 4 + i]
//    }
    }
    const copyFromUint32Array = (pos, a) => {
      mod.HEAP32.set(a, pos / 4)
//    for (let i = 0; i < a.length; i++) {
//      mod.HEAP32[pos / 4 + i] = a[i]
//    }
    }
//////////////////////////////////
    const _wrapGetStr = (func, returnAsStr = true) => {
      return (x, ioMode = 0) => {
        const maxBufSize = 3096
        const stack = mod.stackSave()
        const pos = mod.stackAlloc(maxBufSize)
        const n = func(pos, maxBufSize, x, ioMode)
        if (n <= 0) {
          mod.stackRestore(stack)
          throw new Error('err gen_str:' + x)
        }
        let s = null
        if (returnAsStr) {
          s = ptrToAsciiStr(pos, n)
        } else {
          s = new Uint8Array(mod.HEAP8.subarray(pos, pos + n))
        }
        mod.stackRestore(stack)
        return s
      }
    }
    const _wrapSerialize = func => {
      return _wrapGetStr(func, false)
    }
    const _wrapDeserialize = func => {
      return (x, buf) => {
        const stack = mod.stackSave()
        const pos = mod.stackAlloc(buf.length)
        mod.HEAP8.set(buf, pos)
        const r = func(x, pos, buf.length)
        mod.stackRestore(stack)
        if (r === 0 || r !== buf.length) throw new Error('err _wrapDeserialize', buf)
      }
    }
    /*
      argNum : n
      func(x0, ..., x_(n-1), buf, ioMode)
      => func(x0, ..., x_(n-1), pos, buf.length, ioMode)
    */
    const _wrapInput = (func, argNum, returnValue = false) => {
      return function () {
        const args = [...arguments]
        const buf = args[argNum]
        const typeStr = Object.prototype.toString.apply(buf)
        if (['[object String]', '[object Uint8Array]', '[object Array]'].indexOf(typeStr) < 0) {
          throw new Error(`err bad type:"${typeStr}". Use String or Uint8Array.`)
        }
        const ioMode = args[argNum + 1] // may undefined
        const stack = mod.stackSave()
        const pos = mod.stackAlloc(buf.length)
        if (typeStr === '[object String]') {
          asciiStrToPtr(pos, buf)
        } else {
          mod.HEAP8.set(buf, pos)
        }
        const r = func(...args.slice(0, argNum), pos, buf.length, ioMode)
        mod.stackRestore(stack)
        if (returnValue) return r
        if (r) throw new Error('err _wrapInput ' + buf)
      }
    }
    const callSetter = (func, a, p1, p2) => {
      const stack = mod.stackSave()
      const pos = mod.stackAlloc(a.length * 4)
      func(pos, p1, p2) // p1, p2 may be undefined
      copyToUint32Array(a, pos)
      mod.stackRestore(stack)
    }
    const callGetter = (func, a, p1, p2) => {
      const stack = mod.stackSave()
      const pos = mod.stackAlloc(a.length * 4)
      mod.HEAP32.set(a, pos / 4)
      const s = func(pos, p1, p2)
      mod.stackRestore(stack)
      return s
    }
    const callShare = (func, a, size, vec, id) => {
      const stack = mod.stackSave()
      const pos = a._sallocAndCopy()
      const idPos = id._sallocAndCopy()
      const vecPos = mod.stackAlloc(size * vec.length)
      for (let i = 0; i < vec.length; i++) {
        copyFromUint32Array(vecPos + size * i, vec[i].a_)
      }
      func(pos, vecPos, vec.length, idPos)
      a._save(pos)
      mod.stackRestore(stack)
    }
    const callRecover = (func, a, size, vec, idVec) => {
      const n = vec.length
      if (n != idVec.length) throw ('recover:bad length')
      const stack = mod.stackSave()
      const secPos = a._salloc()
      const vecPos = mod.stackAlloc(size * n)
      const idVecPos = mod.stackAlloc(BLS_ID_SIZE * n)
      for (let i = 0; i < n; i++) {
        copyFromUint32Array(vecPos + size * i, vec[i].a_)
        copyFromUint32Array(idVecPos + BLS_ID_SIZE * i, idVec[i].a_)
      }
      const r = func(secPos, vecPos, idVecPos, n)
      a._save(secPos)
      mod.stackRestore(stack)
      if (r) throw ('callRecover')
    }

    // change curveType
    exports.blsInit = (curveType = exports.ethMode ? exports.BLS12_381 : exports.BN254) => {
      const r = mod._blsInit(curveType, MCLBN_COMPILED_TIME_VAR)
      if (r) throw ('blsInit err ' + r)
    }
    exports.mclBnFr_setLittleEndian = _wrapInput(mod._mclBnFr_setLittleEndian, 1)
    exports.mclBnFr_setLittleEndianMod = _wrapInput(mod._mclBnFr_setLittleEndianMod, 1)
    exports.mclBnFr_setBigEndianMod = _wrapInput(mod._mclBnFr_setBigEndianMod, 1)
    exports.mclBnFr_setStr = _wrapInput(mod._mclBnFr_setStr, 1)
    exports.mclBnFr_getStr = _wrapGetStr(mod._mclBnFr_getStr)
    exports.mclBnFr_deserialize = _wrapDeserialize(mod._mclBnFr_deserialize)
    exports.mclBnFr_serialize = _wrapSerialize(mod._mclBnFr_serialize)
    exports.mclBnFr_setHashOf = _wrapInput(mod._mclBnFr_setHashOf, 1)

    exports.mclBnG1_setStr = _wrapInput(mod._mclBnG1_setStr, 1)
    exports.mclBnG1_getStr = _wrapGetStr(mod._mclBnG1_getStr)
    exports.mclBnG2_setStr = _wrapInput(mod._mclBnG2_setStr, 1)
    exports.mclBnG2_getStr = _wrapGetStr(mod._mclBnG2_getStr)

    exports.getCurveOrder = _wrapGetStr(mod._blsGetCurveOrder)
    exports.getFieldOrder = _wrapGetStr(mod._blsGetFieldOrder)
    exports.setDstG1 = _wrapInput(mod._mclBnG1_setDst, 0)
    exports.setDstG2 = _wrapInput(mod._mclBnG2_setDst, 0)

    exports.blsIdSetDecStr = _wrapInput(mod._blsIdSetDecStr, 1)
    exports.blsIdSetHexStr = _wrapInput(mod._blsIdSetHexStr, 1)
    exports.blsIdGetDecStr = _wrapGetStr(mod._blsIdGetDecStr)
    exports.blsIdGetHexStr = _wrapGetStr(mod._blsIdGetHexStr)

    exports.blsIdSerialize = _wrapSerialize(mod._blsIdSerialize)
    exports.blsSecretKeySerialize = _wrapSerialize(mod._blsSecretKeySerialize)
    exports.blsPublicKeySerialize = _wrapSerialize(mod._blsPublicKeySerialize)
    exports.blsSignatureSerialize = _wrapSerialize(mod._blsSignatureSerialize)

    exports.blsIdDeserialize = _wrapDeserialize(mod._blsIdDeserialize)
    exports.blsSecretKeyDeserialize = _wrapDeserialize(mod._blsSecretKeyDeserialize)
    exports.blsPublicKeyDeserialize = _wrapDeserialize(mod._blsPublicKeyDeserialize)
    exports.blsSignatureDeserialize = _wrapDeserialize(mod._blsSignatureDeserialize)

    exports.blsPublicKeySerializeUncompressed = _wrapSerialize(mod._blsPublicKeySerializeUncompressed)
    exports.blsSignatureSerializeUncompressed = _wrapSerialize(mod._blsSignatureSerializeUncompressed)
    exports.blsPublicKeyDeserializeUncompressed = _wrapDeserialize(mod._blsPublicKeyDeserializeUncompressed)
    exports.blsSignatureDeserializeUncompressed = _wrapDeserialize(mod._blsSignatureDeserializeUncompressed)

    exports.blsSecretKeySetLittleEndian = _wrapInput(mod._blsSecretKeySetLittleEndian, 1)
    exports.blsSecretKeySetLittleEndianMod = _wrapInput(mod._blsSecretKeySetLittleEndianMod, 1)
    exports.blsHashToSecretKey = _wrapInput(mod._blsHashToSecretKey, 1)
    exports.blsSign = _wrapInput(mod._blsSign, 2)
    exports.blsVerify = _wrapInput(mod._blsVerify, 2, true)

    class Common {
      constructor (size) {
        this.a_ = new Uint32Array(size / 4)
      }
      deserializeHexStr (s) {
        this.deserialize(exports.fromHexStr(s))
      }
      serializeToHexStr () {
        return exports.toHexStr(this.serialize())
      }
      dump (msg = '') {
        console.log(msg + this.serializeToHexStr())
      }
      clear () {
        this.a_.fill(0)
      }
      clone () {
        const copy = new this.constructor()
        copy.a_ = this.a_.slice(0)
        return copy
      }
      // stack alloc new array
      _salloc () {
        return mod.stackAlloc(this.a_.length * 4)
      }
      // stack alloc and copy a_ to mod.HEAP32[pos / 4]
      _sallocAndCopy () {
        const pos = this._salloc()
        mod.HEAP32.set(this.a_, pos / 4)
        return pos
      }
      // save pos to a_
      _save (pos) {
        this.a_.set(mod.HEAP32.subarray(pos / 4, pos / 4 + this.a_.length))
      }
      // set parameter (p1, p2 may be undefined)
      _setter (func, p1, p2) {
        const stack = mod.stackSave()
        const pos = this._salloc()
        const r = func(pos, p1, p2)
        this._save(pos)
        mod.stackRestore(stack)
        if (r) throw new Error('_setter err')
      }
      // getter (p1, p2 may be undefined)
      _getter (func, p1, p2) {
        const stack = mod.stackSave()
        const pos = this._sallocAndCopy()
        const s = func(pos, p1, p2)
        mod.stackRestore(stack)
        return s
      }
      _isEqual (func, rhs) {
        const stack = mod.stackSave()
        const xPos = this._sallocAndCopy()
        const yPos = rhs._sallocAndCopy()
        const r = func(xPos, yPos)
        mod.stackRestore(stack)
        return r === 1
      }
      // func(y, this) and return y
      _op1 (func) {
        const y = new this.constructor()
        const stack = mod.stackSave()
        const xPos = this._sallocAndCopy()
        const yPos = y._salloc()
        func(yPos, xPos)
        y._save(yPos)
        mod.stackRestore(stack)
        return y
      }
      // func(z, this, y) and return z
      _op2 (func, y, Cstr = null) {
        const z = Cstr ? new Cstr() : new this.constructor()
        const stack = mod.stackSave()
        const xPos = this._sallocAndCopy()
        const yPos = y._sallocAndCopy()
        const zPos = z._salloc()
        func(zPos, xPos, yPos)
        z._save(zPos)
        mod.stackRestore(stack)
        return z
      }
      // func(self, y)
      _update (func, y) {
        const stack = mod.stackSave()
        const xPos = this._sallocAndCopy()
        const yPos = y._sallocAndCopy()
        func(xPos, yPos)
        this._save(xPos)
        mod.stackRestore(stack)
      }
    }

    exports.Fr = class extends Common {
      constructor () {
        super(MCLBN_FR_SIZE)
      }
      setInt (x) {
        this._setter(mod._mclBnFr_setInt32, x)
      }
      deserialize (s) {
        this._setter(exports.mclBnFr_deserialize, s)
      }
      serialize () {
        return this._getter(exports.mclBnFr_serialize)
      }
      setStr (s, base = 0) {
        this._setter(exports.mclBnFr_setStr, s, base)
      }
      getStr (base = 0) {
        return this._getter(exports.mclBnFr_getStr, base)
      }
      isZero () {
        return this._getter(mod._mclBnFr_isZero) === 1
      }
      isOne () {
        return this._getter(mod._mclBnFr_isOne) === 1
      }
      isEqual (rhs) {
        return this._isEqual(mod._mclBnFr_isEqual, rhs)
      }
      setLittleEndian (s) {
        this._setter(exports.mclBnFr_setLittleEndian, s)
      }
      setLittleEndianMod (s) {
        this._setter(exports.mclBnFr_setLittleEndianMod, s)
      }
      setBigEndianMod (s) {
        this._setter(exports.mclBnFr_setBigEndianMod, s)
      }
      setByCSPRNG () {
        const a = new Uint8Array(MCLBN_FR_SIZE)
        exports.getRandomValues(a)
        this.setLittleEndian(a)
      }
      setHashOf (s) {
        this._setter(exports.mclBnFr_setHashOf, s)
      }
    }
    exports.deserializeHexStrToFr = s => {
      const r = new exports.Fr()
      r.deserializeHexStr(s)
      return r
    }

    exports.Id = class extends Common {
      constructor () {
        super(BLS_ID_SIZE)
      }
      setInt (x) {
        this._setter(mod._blsIdSetInt, x)
      }
      isEqual (rhs) {
        return this._isEqual(mod._blsIdIsEqual, rhs)
      }
      deserialize (s) {
        this._setter(exports.blsIdDeserialize, s)
      }
      serialize () {
        return this._getter(exports.blsIdSerialize)
      }
      setStr (s, base = 10) {
        switch (base) {
          case 10:
            this._setter(exports.blsIdSetDecStr, s)
            return
          case 16:
            this._setter(exports.blsIdSetHexStr, s)
            return
          default:
            throw ('BlsId.setStr:bad base:' + base)
        }
      }
      getStr (base = 10) {
        switch (base) {
          case 10:
            return this._getter(exports.blsIdGetDecStr)
          case 16:
            return this._getter(exports.blsIdGetHexStr)
          default:
            throw ('BlsId.getStr:bad base:' + base)
        }
      }
      setLittleEndian (s) {
        this._setter(exports.blsSecretKeySetLittleEndian, s)
      }
      setLittleEndianMod (s) {
        this._setter(exports.blsSecretKeySetLittleEndianMod, s)
      }
      setByCSPRNG () {
        const a = new Uint8Array(BLS_ID_SIZE)
        exports.getRandomValues(a)
        this.setLittleEndian(a)
      }
    }
    exports.deserializeHexStrToId = s => {
      const r = new exports.Id()
      r.deserializeHexStr(s)
      return r
    }

    exports.SecretKey = class extends Common {
      constructor () {
        super(BLS_SECRETKEY_SIZE)
      }
      setInt (x) {
        this._setter(mod._blsIdSetInt, x) // same as Id
      }
      isZero () {
        return this._getter(mod._blsSecretKeyIsZero) === 1
      }
      isEqual (rhs) {
        return this._isEqual(mod._blsSecretKeyIsEqual, rhs)
      }
      deserialize (s) {
        this._setter(exports.blsSecretKeyDeserialize, s)
      }
      serialize () {
        return this._getter(exports.blsSecretKeySerialize)
      }
      add (rhs) {
        this._update(mod._blsSecretKeyAdd, rhs)
      }
      share (msk, id) {
        callShare(mod._blsSecretKeyShare, this, BLS_SECRETKEY_SIZE, msk, id)
      }
      recover (secVec, idVec) {
        callRecover(mod._blsSecretKeyRecover, this, BLS_SECRETKEY_SIZE, secVec, idVec)
      }
      setHashOf (s) {
        this._setter(exports.blsHashToSecretKey, s)
      }
      setLittleEndian (s) {
        this._setter(exports.blsSecretKeySetLittleEndian, s)
      }
      setLittleEndianMod (s) {
        this._setter(exports.blsSecretKeySetLittleEndianMod, s)
      }
      setByCSPRNG () {
        const a = new Uint8Array(BLS_SECRETKEY_SIZE)
        exports.getRandomValues(a)
        this.setLittleEndian(a)
      }
      getPublicKey () {
        const pub = new exports.PublicKey()
        const stack = mod.stackSave()
        const secPos = this._sallocAndCopy()
        const pubPos = pub._salloc()
        mod._blsGetPublicKey(pubPos, secPos)
        pub._save(pubPos)
        mod.stackRestore(stack)
        return pub
      }
      /*
        input
        m : message (string or Uint8Array)
        return
        BlsSignature
      */
      sign (m) {
        const sig = new exports.Signature()
        const stack = mod.stackSave()
        const secPos = this._sallocAndCopy()
        const sigPos = sig._salloc()
        exports.blsSign(sigPos, secPos, m)
        sig._save(sigPos)
        mod.stackRestore(stack)
        return sig
      }
    }
    exports.deserializeHexStrToSecretKey = s => {
      const r = new exports.SecretKey()
      r.deserializeHexStr(s)
      return r
    }

    exports.PublicKey = class extends Common {
      constructor () {
        super(BLS_PUBLICKEY_SIZE)
      }
      isZero () {
        return this._getter(mod._blsPublicKeyIsZero) === 1
      }
      isEqual (rhs) {
        return this._isEqual(mod._blsPublicKeyIsEqual, rhs)
      }
      deserialize (s) {
        this._setter(exports.blsPublicKeyDeserialize, s)
      }
      serialize () {
        return this._getter(exports.blsPublicKeySerialize)
      }
      setStr (s, base = 0) {
        const func = ETH_MODE ? exports.mclBnG1_setStr : exports.mclBnG2_setStr
        this._setter(func, s, base)
      }
      getStr (base = 0) {
        const func = ETH_MODE ? exports.mclBnG1_getStr : exports.mclBnG2_getStr
        return this._getter(func, base)
      }
      deserializeUncompressed (s) {
        this._setter(exports.blsPublicKeyDeserializeUncompressed, s)
      }
      serializeUncompressed () {
        return this._getter(exports.blsPublicKeySerializeUncompressed)
      }
      add (rhs) {
        this._update(mod._blsPublicKeyAdd, rhs)
      }
      mul (rhs) {
        this._update(mod._blsPublicKeyMul, rhs)
      }
      share (mpk, id) {
        callShare(mod._blsPublicKeyShare, this, BLS_PUBLICKEY_SIZE, mpk, id)
      }
      recover (secVec, idVec) {
        callRecover(mod._blsPublicKeyRecover, this, BLS_PUBLICKEY_SIZE, secVec, idVec)
      }
      isValidOrder () {
        return this._getter(mod._blsPublicKeyIsValidOrder)
      }
      verify (sig, m) {
        const stack = mod.stackSave()
        const pubPos = this._sallocAndCopy()
        const sigPos = sig._sallocAndCopy()
        const r = exports.blsVerify(sigPos, pubPos, m)
        mod.stackRestore(stack)
        return r != 0
      }
    }
    exports.deserializeHexStrToPublicKey = s => {
      const r = new exports.PublicKey()
      r.deserializeHexStr(s)
      return r
    }
    exports.setGeneratorOfPublicKey = pub => {
      const stack = mod.stackSave()
      const pubPos = pub._sallocAndCopy()
      const r = mod._blsSetGeneratorOfPublicKey(pubPos)
      mod.stackRestore(stack)
      if (r !== 0) throw new Error('bad public key')
    }
    exports.getGeneratorOfPublicKey = () => {
      const pub = new exports.PublicKey()
      const stack = mod.stackSave()
      const pubPos = pub._salloc()
      mod._blsGetGeneratorOfPublicKey(pubPos)
      pub._save(pubPos)
      mod.stackRestore(stack)
      return pub
    }
    exports.getGeneratorofPublicKey = () => {
      console.log('WARNING : getGeneratorofPublicKey is renamed to getGeneratorOfPublicKey')
      return exports.getGeneratorOfPublicKey()
    }

    exports.Signature = class extends Common {
      constructor () {
        super(BLS_SIGNATURE_SIZE)
      }
      isZero () {
        return this._getter(mod._blsSignatureIsZero) === 1
      }
      isEqual (rhs) {
        return this._isEqual(mod._blsSignatureIsEqual, rhs)
      }
      deserialize (s) {
        this._setter(exports.blsSignatureDeserialize, s)
      }
      serialize () {
        return this._getter(exports.blsSignatureSerialize)
      }
      deserializeUncompressed (s) {
        this._setter(exports.blsSignatureDeserializeUncompressed, s)
      }
      setStr (s, base = 0) {
        const func = ETH_MODE ? exports.mclBnG2_setStr : exports.mclBnG1_setStr
        this._setter(func, s, base)
      }
      getStr (base = 0) {
        const func = ETH_MODE ? exports.mclBnG2_getStr : exports.mclBnG1_getStr
        return this._getter(func, base)
      }
      serializeUncompressed () {
        return this._getter(exports.blsSignatureSerializeUncompressed)
      }
      add (rhs) {
        this._update(mod._blsSignatureAdd, rhs)
      }
      recover (secVec, idVec) {
        callRecover(mod._blsSignatureRecover, this, BLS_SIGNATURE_SIZE, secVec, idVec)
      }
      isValidOrder () {
        return this._getter(mod._blsSignatureIsValidOrder)
      }
      // this = aggSig
      aggregate (sigVec) {
        const n = sigVec.length
        const stack = mod.stackSave()
        const aggSigPos = this._sallocAndCopy()
        const sigVecPos = mod.stackAlloc(BLS_SIGNATURE_SIZE * n)
        for (let i = 0; i < n; i++) {
          mod.HEAP32.set(sigVec[i].a_, (sigVecPos + BLS_SIGNATURE_SIZE * i) / 4)
        }
        const r = mod._blsAggregateSignature(aggSigPos, sigVecPos, n)
        this._save(aggSigPos)
        mod.stackRestore(stack)
        return r == 1
      }
      // this = aggSig
      fastAggregateVerify (pubVec, msg) {
        const n = pubVec.length
        const msgSize = msg.length
        const stack = mod.stackSave()
        const aggSigPos = this._sallocAndCopy()
        const pubVecPos = mod.stackAlloc(BLS_PUBLICKEY_SIZE * n)
        const msgPos = mod.stackAlloc(msgSize)
        for (let i = 0; i < n; i++) {
          mod.HEAP32.set(pubVec[i].a_, (pubVecPos + BLS_PUBLICKEY_SIZE * i) / 4)
        }
        mod.HEAP8.set(msg, msgPos)
        const r = mod._blsFastAggregateVerify(aggSigPos, pubVecPos, n, msgPos, msgSize)
        mod.stackRestore(stack)
        return r == 1
      }
      // this = aggSig
      // msgVec = (32 * pubVec.length)-size Uint8Array
      aggregateVerifyNoCheck (pubVec, msgVec) {
        const n = pubVec.length
        const msgSize = 32
        if (n == 0 || msgVec.length != msgSize * n) {
          return false
        }
        const stack = mod.stackSave()
        const aggSigPos = this._sallocAndCopy()
        const pubVecPos = mod.stackAlloc(BLS_PUBLICKEY_SIZE * n)
        const msgPos = mod.stackAlloc(msgVec.length)
        for (let i = 0; i < n; i++) {
          mod.HEAP32.set(pubVec[i].a_, (pubVecPos + BLS_PUBLICKEY_SIZE * i) / 4)
        }
        mod.HEAP8.set(msgVec, msgPos)
        const r = mod._blsAggregateVerifyNoCheck(aggSigPos, pubVecPos, msgPos, msgSize, n)
        mod.stackRestore(stack)
        return r == 1
      }
    }
    exports.deserializeHexStrToSignature = s => {
      const r = new exports.Signature()
      r.deserializeHexStr(s)
      return r
    }
    // 1 (draft-05) 2 (draft-06) 3 (draft-07)
    exports.setETHmode = (mode) => {
      if (mod._blsSetETHmode(mode) != 0) throw new Error(`bad setETHmode ${mode}`)
    }
    exports.setETHserialiation = (enable) => {
      mod._mclBn_setETHserialization(enable ? 1 : 0)
    }
    exports.setMapToMode = (mode) => {
      if (mod._mclBn_setMapToMode(mode) != 0) throw new Error(`bad setMapToMode ${mode}`)
    }
    // make setter check the correctness of the order if doVerify
    exports.verifySignatureOrder = (doVerify) => {
      mod._blsSignatureVerifyOrder(doVerify)
    }
    // make setter check the correctness of the order if doVerify
    exports.verifyPublicKeyOrder = (doVerify) => {
      mod._blsPublicKeyVerifyOrder(doVerify)
    }
    exports.areAllMsgDifferent = (msgs, msgSize) => {
      const n = msgs.length / msgSize
      if (msgs.length != n * msgSize) return false
      const h = {}
      for (let i = 0; i < n; i++) {
        const m = msgs.subarray(i * msgSize, (i + 1) * msgSize)
        if (m in h) return false
        h[m] = true
      }
      return true
    }
    /*
      return true if all pub[i].verify(sigs[i], msgs[i])
      msgs is a concatenation of arrays of 32-byte Uint8Array
    */
    exports.multiVerify = (pubs, sigs, msgs) => {
      const MSG_SIZE = 32
      const RAND_SIZE = 8 // 64-bit rand
      const threadNum = 0 // not used
      const n = sigs.length
      if (pubs.length != n || msgs.length != n) return false
      for (let i = 0; i < n; i++) {
        if (msgs[i].length != MSG_SIZE) return false
      }
      const stack = mod.stackSave()
      const sigPos = mod.stackAlloc(BLS_SIGNATURE_SIZE * n)
      const pubPos = mod.stackAlloc(BLS_PUBLICKEY_SIZE * n)
      const msgPos = mod.stackAlloc(MSG_SIZE * n)
      const randPos = mod.stackAlloc(RAND_SIZE * n)

      // getRandomValues accepts only Uint8Array
      const rai = mod.HEAP8.subarray(randPos, randPos + RAND_SIZE * n)
      const rau = new Uint8Array(rai.buffer, randPos, rai.length)
      exports.getRandomValues(rau)
      for (let i = 0; i < n; i++) {
        mod.HEAP32.set(sigs[i].a_, (sigPos + BLS_SIGNATURE_SIZE * i) / 4)
        mod.HEAP32.set(pubs[i].a_, (pubPos + BLS_PUBLICKEY_SIZE * i) / 4)
        mod.HEAP8.set(msgs[i], msgPos + MSG_SIZE * i)
      }
      const r = mod._blsMultiVerify(sigPos, pubPos, msgPos, MSG_SIZE, randPos, RAND_SIZE, n, threadNum)

      mod.stackRestore(stack)
      return r == 1
    }
    exports.blsInit(curveType)
    if (exports.ethMode) {
      exports.setETHmode(exports.ETH_MODE_DRAFT_07)
    }
    exports.neg = x => {
      if (x instanceof exports.Fr) {
        return x._op1(mod._mclBnFr_neg)
      }
      throw new Error('neg:bad type')
    }
    exports.sqr = x => {
      if (x instanceof exports.Fr) {
        return x._op1(mod._mclBnFr_sqr)
      }
      throw new Error('sqr:bad type')
    }
    exports.inv = x => {
      if (x instanceof exports.Fr) {
        return x._op1(mod._mclBnFr_inv)
      }
      throw new Error('inv:bad type')
    }
    exports.add = (x, y) => {
      if (x.constructor !== y.constructor) throw new Error('add:mismatch type')
      if (x instanceof exports.Fr) {
        return x._op2(mod._mclBnFr_add, y)
      }
      throw new Error('add:bad type')
    }
    exports.sub = (x, y) => {
      if (x.constructor !== y.constructor) throw new Error('sub:mismatch type')
      if (x instanceof exports.Fr) {
        return x._op2(mod._mclBnFr_sub, y)
      }
      throw new Error('sub:bad type')
    }
    /*
      Fr * Fr
    */
    exports.mul = (x, y) => {
      if (x instanceof exports.Fr && y instanceof exports.Fr) {
        return x._op2(mod._mclBnFr_mul, y)
      }
      throw new Error('mul:mismatch type')
    }
    exports.div = (x, y) => {
      if (x.constructor !== y.constructor) throw new Error('div:mismatch type')
      if (x instanceof exports.Fr) {
        return x._op2(mod._mclBnFr_div, y)
      }
      throw new Error('div:bad type')
    }
    exports.hashToFr = s => {
      const x = new exports.Fr()
      x.setHashOf(s)
      return x
    }
  } // blsSetup()

  // glue.js calls this with a Uint8Array to be filled
  const _cryptoGetRandomValues = function(a) {
    exports.getRandomValues(a)
  }
  // f(a:array) fills a with random value
  exports.setRandFunc = f => {
    exports.getRandomValues = f
  }
  exports.init = async (curveType = exports.ethMode ? exports.BLS12_381 : exports.BN254) => {
    exports.curveType = curveType
    exports.getRandomValues = crypto.getRandomValues.bind(crypto)
    exports.mod = await createModule({
      cryptoGetRandomValues: _cryptoGetRandomValues,
    })
    blsSetup(exports, curveType)
  }
  return exports
}

module.exports = _blsSetupFactory
