# CHANGELOG.md

## 0.3.0 (unreleased)

Features:

  - upgrade to eth2 spec 0.10.1
  - add uncompressed serialization and deserialization (PublicKey, Signature)

## 0.2.1 (2020-01-29)

Bugfixes:

  - removed global process unhandled exception and rejection handling which would modify stacktraces on exceptions unreleated to bls