[![Build Status](https://travis-ci.org/herumi/bls-wasm.png)](https://travis-ci.org/herumi/bls-wasm)
# BLS signature for Node.js by WebAssembly

# Abstract

- Fr : SecretKey, G2 : PublicKey, G1 : Signature
- see [bls-eth-wasm](https://github.com/herumi/bls-eth-wasm) if you need Ethereum 2.0 compatible sign/verify.
- see [bls](https://github.com/herumi/bls) and [BLS demo on browser](https://herumi.github.io/bls-wasm/browser/demo.html)

## How to use
The version `v0.4.2` breaks backward compatibility of the entry point.

- Node.js : `const bls = require('bls-wasm')`
- React : `const bls = require('bls-wasm/browser')`
- HTML : `<script src="https://herumi.github.io/bls-wasm/browser/bls.js"></script>`

## for Node.js
```
node test/test.js
```

## for browser

Include `browser/bls.js`

## for React

```
const bls = require('bls-wasm/browser')
```

# License

modified new BSD License
http://opensource.org/licenses/BSD-3-Clause

# Author

MITSUNARI Shigeo(herumi@nifty.com)

# Sponsors welcome
[GitHub Sponsor](https://github.com/sponsors/herumi)
