(generator => {
  if (typeof window === 'object') {
    const exports = {}
    window.bls = generator(exports, false)
  } else {
    generator(exports, true)
  }
})((exports, isNodeJs) => {
  /* eslint-disable */
  exports.BN254 = 0
  exports.BN381_1 = 1
  exports.BLS12_381 = 5
  exports.ethMode = false
  exports.ETH_MODE_DRAFT_05 = 1
  exports.ETH_MODE_DRAFT_06 = 2
  exports.ETH_MODE_DRAFT_07 = 3

  const setup = (exports, curveType) => {
    const mod = exports.mod
    const MCLBN_FP_UNIT_SIZE = 6
    const MCLBN_FR_UNIT_SIZE = exports.ethMode ? 4 : 6
    const BLS_COMPILER_TIME_VAR_ADJ = exports.ethMode ? 200 : 0
    const MCLBN_COMPILED_TIME_VAR = (MCLBN_FR_UNIT_SIZE * 10 + MCLBN_FP_UNIT_SIZE) + BLS_COMPILER_TIME_VAR_ADJ
    const BLS_ID_SIZE = MCLBN_FR_UNIT_SIZE * 8
    const BLS_SECRETKEY_SIZE = MCLBN_FP_UNIT_SIZE * 8
    const BLS_PUBLICKEY_SIZE = BLS_SECRETKEY_SIZE * 3 * (exports.ethMode ? 1 : 2)
    const BLS_SIGNATURE_SIZE = BLS_SECRETKEY_SIZE * 3 * (exports.ethMode ? 2 : 1)

    const _malloc = size => {
      return mod._blsMalloc(size)
    }
    const _free = pos => {
      mod._blsFree(pos)
    }
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
        const pos = _malloc(maxBufSize)
        const n = func(pos, maxBufSize, x, ioMode)
        if (n <= 0) {
          throw new Error('err gen_str:' + x)
        }
        let s = null
        if (returnAsStr) {
          s = ptrToAsciiStr(pos, n)
        } else {
          s = new Uint8Array(mod.HEAP8.subarray(pos, pos + n))
        }
        _free(pos)
        return s
      }
    }
    const _wrapSerialize = func => {
      return _wrapGetStr(func, false)
    }
    const _wrapDeserialize = func => {
      return (x, buf) => {
        const pos = _malloc(buf.length)
        mod.HEAP8.set(buf, pos)
        const r = func(x, pos, buf.length)
        _free(pos)
        if (r === 0) throw new Error('err _wrapDeserialize', buf)
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
        const pos = _malloc(buf.length)
        if (typeStr === '[object String]') {
          asciiStrToPtr(pos, buf)
        } else {
          mod.HEAP8.set(buf, pos)
        }
        const r = func(...args.slice(0, argNum), pos, buf.length, ioMode)
        _free(pos)
        if (returnValue) return r
        if (r) throw new Error('err _wrapInput ' + buf)
      }
    }
    const callSetter = (func, a, p1, p2) => {
      const pos = _malloc(a.length * 4)
      func(pos, p1, p2) // p1, p2 may be undefined
      copyToUint32Array(a, pos)
      _free(pos)
    }
    const callGetter = (func, a, p1, p2) => {
      const pos = _malloc(a.length * 4)
      mod.HEAP32.set(a, pos / 4)
      const s = func(pos, p1, p2)
      _free(pos)
      return s
    }
    const callShare = (func, a, size, vec, id) => {
      const pos = a._allocAndCopy()
      const idPos = id._allocAndCopy()
      const vecPos = _malloc(size * vec.length)
      for (let i = 0; i < vec.length; i++) {
        copyFromUint32Array(vecPos + size * i, vec[i].a_)
      }
      func(pos, vecPos, vec.length, idPos)
      _free(vecPos)
      _free(idPos)
      a._saveAndFree(pos)
    }
    const callRecover = (func, a, size, vec, idVec) => {
      const n = vec.length
      if (n != idVec.length) throw ('recover:bad length')
      const secPos = a._alloc()
      const vecPos = _malloc(size * n)
      const idVecPos = _malloc(BLS_ID_SIZE * n)
      for (let i = 0; i < n; i++) {
        copyFromUint32Array(vecPos + size * i, vec[i].a_)
        copyFromUint32Array(idVecPos + BLS_ID_SIZE * i, idVec[i].a_)
      }
      const r = func(secPos, vecPos, idVecPos, n)
      _free(idVecPos)
      _free(vecPos)
      a._saveAndFree(secPos)
      if (r) throw ('callRecover')
    }

    // change curveType
    exports.blsInit = (curveType = exports.ethMode ? exports.BLS12_381 : exports.BN254) => {
      const r = mod._blsInit(curveType, MCLBN_COMPILED_TIME_VAR)
      if (r) throw ('blsInit err ' + r)
    }
    exports.getCurveOrder = _wrapGetStr(mod._blsGetCurveOrder)
    exports.getFieldOrder = _wrapGetStr(mod._blsGetFieldOrder)

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
      // alloc new array
      _alloc () {
        return _malloc(this.a_.length * 4)
      }
      // alloc and copy a_ to mod.HEAP32[pos / 4]
      _allocAndCopy () {
        const pos = this._alloc()
        mod.HEAP32.set(this.a_, pos / 4)
        return pos
      }
      // save pos to a_
      _save (pos) {
        this.a_.set(mod.HEAP32.subarray(pos / 4, pos / 4 + this.a_.length))
      }
      // save and free
      _saveAndFree(pos) {
        this._save(pos)
        _free(pos)
      }
      // set parameter (p1, p2 may be undefined)
      _setter (func, p1, p2) {
        const pos = this._alloc()
        const r = func(pos, p1, p2)
        this._saveAndFree(pos)
        if (r) throw new Error('_setter err')
      }
      // getter (p1, p2 may be undefined)
      _getter (func, p1, p2) {
        const pos = this._allocAndCopy()
        const s = func(pos, p1, p2)
        _free(pos)
        return s
      }
      _isEqual (func, rhs) {
        const xPos = this._allocAndCopy()
        const yPos = rhs._allocAndCopy()
        const r = func(xPos, yPos)
        _free(yPos)
        _free(xPos)
        return r === 1
      }
      // func(y, this) and return y
      _op1 (func) {
        const y = new this.constructor()
        const xPos = this._allocAndCopy()
        const yPos = y._alloc()
        func(yPos, xPos)
        y._saveAndFree(yPos)
        _free(xPos)
        return y
      }
      // func(z, this, y) and return z
      _op2 (func, y, Cstr = null) {
        const z = Cstr ? new Cstr() : new this.constructor()
        const xPos = this._allocAndCopy()
        const yPos = y._allocAndCopy()
        const zPos = z._alloc()
        func(zPos, xPos, yPos)
        z._saveAndFree(zPos)
        _free(yPos)
        _free(xPos)
        return z
      }
      // func(self, y)
      _update (func, y) {
        const xPos = this._allocAndCopy()
        const yPos = y._allocAndCopy()
        func(xPos, yPos)
        _free(yPos)
        this._saveAndFree(xPos)
      }
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
        const secPos = this._allocAndCopy()
        const pubPos = pub._alloc()
        mod._blsGetPublicKey(pubPos, secPos)
        pub._saveAndFree(pubPos)
        _free(secPos)
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
        const secPos = this._allocAndCopy()
        const sigPos = sig._alloc()
        exports.blsSign(sigPos, secPos, m)
        sig._saveAndFree(sigPos)
        _free(secPos)
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
      deserializeUncompressed (s) {
        this._setter(exports.blsPublicKeyDeserializeUncompressed, s)
      }
      serializeUncompressed () {
        return this._getter(exports.blsPublicKeySerializeUncompressed)
      }
      add (rhs) {
        this._update(mod._blsPublicKeyAdd, rhs)
      }
      share (msk, id) {
        callShare(mod._blsPublicKeyShare, this, BLS_PUBLICKEY_SIZE, msk, id)
      }
      recover (secVec, idVec) {
        callRecover(mod._blsPublicKeyRecover, this, BLS_PUBLICKEY_SIZE, secVec, idVec)
      }
      isValidOrder () {
        return this._getter(mod._blsPublicKeyIsValidOrder)
      }
      verify (sig, m) {
        const pubPos = this._allocAndCopy()
        const sigPos = sig._allocAndCopy()
        const r = exports.blsVerify(sigPos, pubPos, m)
        _free(sigPos)
        _free(pubPos)
        return r != 0
      }
    }
    exports.deserializeHexStrToPublicKey = s => {
      const r = new exports.PublicKey()
      r.deserializeHexStr(s)
      return r
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
        const aggSigPos = this._allocAndCopy()
        const sigVecPos = _malloc(BLS_SIGNATURE_SIZE * n)
        for (let i = 0; i < n; i++) {
          mod.HEAP32.set(sigVec[i].a_, (sigVecPos + BLS_SIGNATURE_SIZE * i) / 4)
        }
        const r = mod._blsAggregateSignature(aggSigPos, sigVecPos, n)
        _free(sigVecPos)
        this._saveAndFree(aggSigPos)
        return r == 1
      }
      // this = aggSig
      fastAggregateVerify (pubVec, msg) {
        const n = pubVec.length
        const msgSize = msg.length
        const aggSigPos = this._allocAndCopy()
        const pubVecPos = _malloc(BLS_PUBLICKEY_SIZE * n)
        const msgPos = _malloc(msgSize)
        for (let i = 0; i < n; i++) {
          mod.HEAP32.set(pubVec[i].a_, (pubVecPos + BLS_PUBLICKEY_SIZE * i) / 4)
        }
        mod.HEAP8.set(msg, msgPos)
        const r = mod._blsFastAggregateVerify(aggSigPos, pubVecPos, n, msgPos, msgSize)
        _free(msgPos)
        _free(pubVecPos)
        _free(aggSigPos)
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
        const aggSigPos = this._allocAndCopy()
        const pubVecPos = _malloc(BLS_PUBLICKEY_SIZE * n)
        const msgPos = _malloc(msgVec.length)
        for (let i = 0; i < n; i++) {
          mod.HEAP32.set(pubVec[i].a_, (pubVecPos + BLS_PUBLICKEY_SIZE * i) / 4)
        }
        mod.HEAP8.set(msgVec, msgPos)
        const r = mod._blsAggregateVerifyNoCheck(aggSigPos, pubVecPos, msgPos, msgSize, n)
        _free(msgPos)
        _free(pubVecPos)
        _free(aggSigPos)
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
      h = {}
      for (let i = 0; i < n; i++) {
        const m = msgs.subarray(i * msgSize, (i + 1) * msgSize)
        if (m in h) return false
        h[m] = true
      }
      return true
    }
    /*
      return true if all pub[i].verify(sigs[i], msgs[i])
      msgs is array of 32-byte Uint8Array
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
      const sigPos = _malloc(BLS_SIGNATURE_SIZE * n)
      const pubPos = _malloc(BLS_PUBLICKEY_SIZE * n)
      const msgPos = _malloc(MSG_SIZE * n)
      const randPos = _malloc(RAND_SIZE * n)

      exports.getRandomValues(mod.HEAP8.subarray(randPos, randPos + RAND_SIZE * n))
      for (let i = 0; i < n; i++) {
        mod.HEAP32.set(sigs[i].a_, (sigPos + BLS_SIGNATURE_SIZE * i) / 4)
        mod.HEAP32.set(pubs[i].a_, (pubPos + BLS_PUBLICKEY_SIZE * i) / 4)
        mod.HEAP8.set(msgs[i], msgPos + MSG_SIZE * i)
      }
      const r = mod._blsMultiVerify(sigPos, pubPos, msgPos, MSG_SIZE, randPos, RAND_SIZE, n, threadNum)

      _free(randPos)
      _free(msgPos)
      _free(pubPos)
      _free(sigPos)
      return r == 1
    }
    exports.blsInit(curveType)
    if (exports.ethMode) {
      exports.setETHmode(exports.ETH_MODE_DRAFT_07)
    }
  } // setup()
  const _cryptoGetRandomValues = function(p, n) {
    const a = new Uint8Array(n)
    exports.getRandomValues(a)
    for (let i = 0; i < n; i++) {
      exports.mod.HEAP8[p + i] = a[i]
    }
  }
  // f(a:array) fills a with random value
  exports.setRandFunc = f => {
    exports.getRandomValues = f
  }
  exports.init = (curveType = exports.BN254) => {
    exports.curveType = curveType
    const name = 'bls_c'
    return new Promise(resolve => {
      if (isNodeJs) {
        const crypto = require('crypto')
        exports.getRandomValues = crypto.randomFillSync
        const path = require('path')
        const js = require(`./${name}.js`)
        const Module = {
          cryptoGetRandomValues : _cryptoGetRandomValues,
          locateFile: baseName => { return path.join(__dirname, baseName) }
        }
        js(Module)
          .then(_mod => {
            exports.mod = _mod
            setup(exports, curveType)
            resolve()
          })
      } else {
        const crypto = window.crypto || window.msCrypto
        exports.getRandomValues = x => crypto.getRandomValues(x)
        fetch(`./${name}.wasm`) // eslint-disable-line
          .then(response => response.arrayBuffer())
          .then(buffer => new Uint8Array(buffer))
          .then(() => {
            exports.mod = Module() // eslint-disable-line
            exports.mod.cryptoGetRandomValues = _cryptoGetRandomValues
            exports.mod.onRuntimeInitialized = () => {
              setup(exports, curveType)
              resolve()
            }
          })
      }
    })
  }
  return exports
})
