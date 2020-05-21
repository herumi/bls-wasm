# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
TBD

## [0.5.0] (2020-05-21)

- update to bls draft v7 (eth2 0.12.x spec support)

## [0.4.0] (2020-02-11)

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


## [0.3.0] (2020-02-03)

Features:

  - upgrade to eth2 spec 0.10.1
  - add uncompressed serialization and deserialization (PublicKey, Signature)

## [0.2.1] (2020-01-29)

Bugfixes:

  - removed global process unhandled exception and rejection handling which would modify stacktraces on exceptions unreleated to bls

[Unreleased]: https://github.com/ChainSafe/eth2-bls-wasm/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/ChainSafe/eth2-bls-wasm/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/ChainSafe/eth2-bls-wasm/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/ChainSafe/eth2-bls-wasm/compare/0.2.1...v0.3.0
