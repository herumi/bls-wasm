# CHANGELOG.md

## 0.4.0 (2020-02-11)

###Added:
- PublicKey.isValidOrder
- Signature.isValidOrder
- Signature.aggregate
- Signature.aggregateVerifyNoCheck
- Signature.fastAggregateVerify
- verifySignatureOrder
- verifyPublicKeyOrder
- areAllMsgDifferent

###Bugfixes:
- msg sizes changed to 32
- changed order of lib initialization

###Other:
- bls submodule changed to herumi's


## 0.3.0 (2020-02-03)

Features:

  - upgrade to eth2 spec 0.10.1
  - add uncompressed serialization and deserialization (PublicKey, Signature)

## 0.2.1 (2020-01-29)

Bugfixes:

  - removed global process unhandled exception and rejection handling which would modify stacktraces on exceptions unreleated to bls
