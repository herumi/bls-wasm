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
    // shared wrappers defined in mcl/src/wasm/glue.js (embedded in bls_c.js);
    // values are passed as Uint32Array (a_) and the stack is restored in finally
    const stackSave = mod.stackSave
    const stackAlloc = mod.stackAlloc
    const stackRestore = mod.stackRestore
    const sallocCopy = mod.sallocCopy
    const sallocBytes = mod.sallocBytes
    const sallocArray = mod.sallocArray
    const copyFromHeap32 = mod.copyFromHeap32
    const callSetter = mod.callSetter
    const callGetter = mod.callGetter
    const callGetter2 = mod.callGetter2
    const callOp1 = mod.callOp1
    const callOp2 = mod.callOp2
    const callUpdate = mod.callUpdate
    const callOp1Input = mod.callOp1Input
    const callGetter2Input = mod.callGetter2Input
    const callShare = mod.callShare
    const callRecover = mod.callRecover
    const callSetInput = mod.callSetInput
    const callGetStr = mod.callGetStr
    const callDeserialize = mod.callDeserialize
    const callSerialize = mod.callSerialize
    // array of the internal buffers of v (for sallocArray / callShare / callRecover)
    const _toArrays = v => v.map(x => x.a_)

    // change curveType
    exports.blsInit = (curveType = exports.ethMode ? exports.BLS12_381 : exports.BN254) => {
      const r = mod._blsInit(curveType, MCLBN_COMPILED_TIME_VAR)
      if (r) throw ('blsInit err ' + r)
    }
    exports.mclBnFr_setLittleEndian = mod.wrapInput(mod._mclBnFr_setLittleEndian, 1)
    exports.mclBnFr_setLittleEndianMod = mod.wrapInput(mod._mclBnFr_setLittleEndianMod, 1)
    exports.mclBnFr_setBigEndianMod = mod.wrapInput(mod._mclBnFr_setBigEndianMod, 1)
    exports.mclBnFr_setStr = mod.wrapInput(mod._mclBnFr_setStr, 1)
    exports.mclBnFr_getStr = mod.wrapGetStr(mod._mclBnFr_getStr)
    exports.mclBnFr_deserialize = mod.wrapDeserialize(mod._mclBnFr_deserialize)
    exports.mclBnFr_serialize = mod.wrapSerialize(mod._mclBnFr_serialize)
    exports.mclBnFr_setHashOf = mod.wrapInput(mod._mclBnFr_setHashOf, 1)

    exports.mclBnG1_setStr = mod.wrapInput(mod._mclBnG1_setStr, 1)
    exports.mclBnG1_getStr = mod.wrapGetStr(mod._mclBnG1_getStr)
    exports.mclBnG2_setStr = mod.wrapInput(mod._mclBnG2_setStr, 1)
    exports.mclBnG2_getStr = mod.wrapGetStr(mod._mclBnG2_getStr)

    exports.getCurveOrder = mod.wrapGetStr(mod._blsGetCurveOrder)
    exports.getFieldOrder = mod.wrapGetStr(mod._blsGetFieldOrder)
    exports.setDstG1 = mod.wrapInput(mod._mclBnG1_setDst, 0)
    exports.setDstG2 = mod.wrapInput(mod._mclBnG2_setDst, 0)

    exports.blsIdSetDecStr = mod.wrapInput(mod._blsIdSetDecStr, 1)
    exports.blsIdSetHexStr = mod.wrapInput(mod._blsIdSetHexStr, 1)
    exports.blsIdGetDecStr = mod.wrapGetStr(mod._blsIdGetDecStr)
    exports.blsIdGetHexStr = mod.wrapGetStr(mod._blsIdGetHexStr)

    exports.blsIdSerialize = mod.wrapSerialize(mod._blsIdSerialize)
    exports.blsSecretKeySerialize = mod.wrapSerialize(mod._blsSecretKeySerialize)
    exports.blsPublicKeySerialize = mod.wrapSerialize(mod._blsPublicKeySerialize)
    exports.blsSignatureSerialize = mod.wrapSerialize(mod._blsSignatureSerialize)

    exports.blsIdDeserialize = mod.wrapDeserialize(mod._blsIdDeserialize)
    exports.blsSecretKeyDeserialize = mod.wrapDeserialize(mod._blsSecretKeyDeserialize)
    exports.blsPublicKeyDeserialize = mod.wrapDeserialize(mod._blsPublicKeyDeserialize)
    exports.blsSignatureDeserialize = mod.wrapDeserialize(mod._blsSignatureDeserialize)

    exports.blsPublicKeySerializeUncompressed = mod.wrapSerialize(mod._blsPublicKeySerializeUncompressed)
    exports.blsSignatureSerializeUncompressed = mod.wrapSerialize(mod._blsSignatureSerializeUncompressed)
    exports.blsPublicKeyDeserializeUncompressed = mod.wrapDeserialize(mod._blsPublicKeyDeserializeUncompressed)
    exports.blsSignatureDeserializeUncompressed = mod.wrapDeserialize(mod._blsSignatureDeserializeUncompressed)

    exports.blsSecretKeySetLittleEndian = mod.wrapInput(mod._blsSecretKeySetLittleEndian, 1)
    exports.blsSecretKeySetLittleEndianMod = mod.wrapInput(mod._blsSecretKeySetLittleEndianMod, 1)
    exports.blsHashToSecretKey = mod.wrapInput(mod._blsHashToSecretKey, 1)
    exports.blsSign = mod.wrapInput(mod._blsSign, 2)
    exports.blsVerify = mod.wrapInput(mod._blsVerify, 2, true)

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
        return mod.salloc(this.a_)
      }
      // stack alloc and copy a_
      _sallocAndCopy () {
        return sallocCopy(this.a_)
      }
      // save pos to a_
      _save (pos) {
        copyFromHeap32(this.a_, pos)
      }
      // this = func(p1, p2) ; throw if func returns non-zero (p1, p2 may be undefined)
      _setter (func, p1, p2) {
        callSetter(func, this.a_, p1, p2)
      }
      // return func(this, p1, p2)
      _getter (func, p1, p2) {
        return callGetter(func, this.a_, p1, p2)
      }
      _isEqual (func, rhs) {
        return callGetter2(func, this.a_, rhs.a_) === 1
      }
      // y = func(this) and return y
      _op1 (func) {
        const y = new this.constructor()
        callOp1(func, y.a_, this.a_)
        return y
      }
      // z = func(this, y) and return z
      _op2 (func, y, Cstr = null) {
        const z = Cstr ? new Cstr() : new this.constructor()
        callOp2(func, z.a_, this.a_, y.a_)
        return z
      }
      // this = func(this, y)
      _update (func, y) {
        callUpdate(func, this.a_, y.a_)
      }
      // this = func(buf [, ioMode]) ; buf is a string or Uint8Array
      _setInput (func, buf, ioMode) {
        callSetInput(func, this.a_, buf, ioMode)
      }
      // return the string of this
      _getStr (func, ioMode) {
        return callGetStr(func, this.a_, ioMode)
      }
      _deserialize (func, buf) {
        callDeserialize(func, this.a_, buf)
      }
      _serialize (func) {
        return callSerialize(func, this.a_)
      }
      // this = recover(vec, idVec) ; bls C API takes (out, vec, idVec, n)
      // while glue callRecover calls func(out, idVec, vec, n) (mcl order)
      _recover (func, vec, idVec) {
        const r = callRecover((y, idVecPos, vecPos, n) => func(y, vecPos, idVecPos, n), this.a_, _toArrays(idVec), _toArrays(vec))
        if (r) throw new Error('callRecover')
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
        this._deserialize(mod._mclBnFr_deserialize, s)
      }
      serialize () {
        return this._serialize(mod._mclBnFr_serialize)
      }
      setStr (s, base = 0) {
        this._setInput(mod._mclBnFr_setStr, s, base)
      }
      getStr (base = 0) {
        return this._getStr(mod._mclBnFr_getStr, base)
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
        this._setInput(mod._mclBnFr_setLittleEndian, s)
      }
      setLittleEndianMod (s) {
        this._setInput(mod._mclBnFr_setLittleEndianMod, s)
      }
      setBigEndianMod (s) {
        this._setInput(mod._mclBnFr_setBigEndianMod, s)
      }
      setByCSPRNG () {
        const a = new Uint8Array(MCLBN_FR_SIZE)
        exports.getRandomValues(a)
        this.setLittleEndian(a)
      }
      setHashOf (s) {
        this._setInput(mod._mclBnFr_setHashOf, s)
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
        this._deserialize(mod._blsIdDeserialize, s)
      }
      serialize () {
        return this._serialize(mod._blsIdSerialize)
      }
      setStr (s, base = 10) {
        switch (base) {
          case 10:
            this._setInput(mod._blsIdSetDecStr, s)
            return
          case 16:
            this._setInput(mod._blsIdSetHexStr, s)
            return
          default:
            throw ('BlsId.setStr:bad base:' + base)
        }
      }
      getStr (base = 10) {
        switch (base) {
          case 10:
            return this._getStr(mod._blsIdGetDecStr)
          case 16:
            return this._getStr(mod._blsIdGetHexStr)
          default:
            throw ('BlsId.getStr:bad base:' + base)
        }
      }
      setLittleEndian (s) {
        this._setInput(mod._blsSecretKeySetLittleEndian, s)
      }
      setLittleEndianMod (s) {
        this._setInput(mod._blsSecretKeySetLittleEndianMod, s)
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
        this._deserialize(mod._blsSecretKeyDeserialize, s)
      }
      serialize () {
        return this._serialize(mod._blsSecretKeySerialize)
      }
      add (rhs) {
        this._update(mod._blsSecretKeyAdd, rhs)
      }
      share (msk, id) {
        callShare(mod._blsSecretKeyShare, this.a_, _toArrays(msk), id.a_)
      }
      recover (secVec, idVec) {
        this._recover(mod._blsSecretKeyRecover, secVec, idVec)
      }
      setHashOf (s) {
        this._setInput(mod._blsHashToSecretKey, s)
      }
      setLittleEndian (s) {
        this._setInput(mod._blsSecretKeySetLittleEndian, s)
      }
      setLittleEndianMod (s) {
        this._setInput(mod._blsSecretKeySetLittleEndianMod, s)
      }
      setByCSPRNG () {
        const a = new Uint8Array(BLS_SECRETKEY_SIZE)
        exports.getRandomValues(a)
        this.setLittleEndian(a)
      }
      getPublicKey () {
        const pub = new exports.PublicKey()
        callOp1(mod._blsGetPublicKey, pub.a_, this.a_)
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
        callOp1Input(mod._blsSign, sig.a_, this.a_, m)
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
        this._deserialize(mod._blsPublicKeyDeserialize, s)
      }
      serialize () {
        return this._serialize(mod._blsPublicKeySerialize)
      }
      setStr (s, base = 0) {
        const func = ETH_MODE ? mod._mclBnG1_setStr : mod._mclBnG2_setStr
        this._setInput(func, s, base)
      }
      getStr (base = 0) {
        const func = ETH_MODE ? mod._mclBnG1_getStr : mod._mclBnG2_getStr
        return this._getStr(func, base)
      }
      deserializeUncompressed (s) {
        this._deserialize(mod._blsPublicKeyDeserializeUncompressed, s)
      }
      serializeUncompressed () {
        return this._serialize(mod._blsPublicKeySerializeUncompressed)
      }
      add (rhs) {
        this._update(mod._blsPublicKeyAdd, rhs)
      }
      mul (rhs) {
        this._update(mod._blsPublicKeyMul, rhs)
      }
      share (mpk, id) {
        callShare(mod._blsPublicKeyShare, this.a_, _toArrays(mpk), id.a_)
      }
      recover (secVec, idVec) {
        this._recover(mod._blsPublicKeyRecover, secVec, idVec)
      }
      isValidOrder () {
        return this._getter(mod._blsPublicKeyIsValidOrder)
      }
      verify (sig, m) {
        return callGetter2Input(mod._blsVerify, sig.a_, this.a_, m) != 0
      }
    }
    exports.deserializeHexStrToPublicKey = s => {
      const r = new exports.PublicKey()
      r.deserializeHexStr(s)
      return r
    }
    exports.setGeneratorOfPublicKey = pub => {
      const r = callGetter(mod._blsSetGeneratorOfPublicKey, pub.a_)
      if (r !== 0) throw new Error('bad public key')
    }
    exports.getGeneratorOfPublicKey = () => {
      const pub = new exports.PublicKey()
      callSetter(mod._blsGetGeneratorOfPublicKey, pub.a_)
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
        this._deserialize(mod._blsSignatureDeserialize, s)
      }
      serialize () {
        return this._serialize(mod._blsSignatureSerialize)
      }
      deserializeUncompressed (s) {
        this._deserialize(mod._blsSignatureDeserializeUncompressed, s)
      }
      setStr (s, base = 0) {
        const func = ETH_MODE ? mod._mclBnG2_setStr : mod._mclBnG1_setStr
        this._setInput(func, s, base)
      }
      getStr (base = 0) {
        const func = ETH_MODE ? mod._mclBnG2_getStr : mod._mclBnG1_getStr
        return this._getStr(func, base)
      }
      serializeUncompressed () {
        return this._serialize(mod._blsSignatureSerializeUncompressed)
      }
      add (rhs) {
        this._update(mod._blsSignatureAdd, rhs)
      }
      recover (secVec, idVec) {
        this._recover(mod._blsSignatureRecover, secVec, idVec)
      }
      isValidOrder () {
        return this._getter(mod._blsSignatureIsValidOrder)
      }
      // this = aggSig
      aggregate (sigVec) {
        const n = sigVec.length
        if (n == 0) return false
        const stack = stackSave()
        let r
        try {
          const aggSigPos = sallocCopy(this.a_)
          const sigVecPos = sallocArray(_toArrays(sigVec))
          r = mod._blsAggregateSignature(aggSigPos, sigVecPos, n)
          copyFromHeap32(this.a_, aggSigPos)
        } finally {
          stackRestore(stack)
        }
        return r == 1
      }
      // this = aggSig
      fastAggregateVerify (pubVec, msg) {
        const n = pubVec.length
        if (n == 0) return false
        const msgSize = msg.length
        const stack = stackSave()
        try {
          const aggSigPos = sallocCopy(this.a_)
          const pubVecPos = sallocArray(_toArrays(pubVec))
          const msgPos = sallocBytes(msg)
          return mod._blsFastAggregateVerify(aggSigPos, pubVecPos, n, msgPos, msgSize) == 1
        } finally {
          stackRestore(stack)
        }
      }
      // this = aggSig
      // msgVec = (32 * pubVec.length)-size Uint8Array
      aggregateVerifyNoCheck (pubVec, msgVec) {
        const n = pubVec.length
        const msgSize = 32
        if (n == 0 || msgVec.length != msgSize * n) {
          return false
        }
        const stack = stackSave()
        try {
          const aggSigPos = sallocCopy(this.a_)
          const pubVecPos = sallocArray(_toArrays(pubVec))
          const msgPos = sallocBytes(msgVec)
          return mod._blsAggregateVerifyNoCheck(aggSigPos, pubVecPos, msgPos, msgSize, n) == 1
        } finally {
          stackRestore(stack)
        }
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
      if (n == 0) return false
      const stack = stackSave()
      try {
        const sigPos = sallocArray(_toArrays(sigs))
        const pubPos = sallocArray(_toArrays(pubs))
        const msgPos = stackAlloc(MSG_SIZE * n)
        const randPos = stackAlloc(RAND_SIZE * n)
        const HEAP8 = mod.HEAP8
        for (let i = 0; i < n; i++) {
          HEAP8.set(msgs[i], msgPos + MSG_SIZE * i)
        }
        // getRandomValues accepts only Uint8Array
        exports.getRandomValues(new Uint8Array(HEAP8.buffer, randPos, RAND_SIZE * n))
        return mod._blsMultiVerify(sigPos, pubPos, msgPos, MSG_SIZE, randPos, RAND_SIZE, n, threadNum) == 1
      } finally {
        stackRestore(stack)
      }
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
