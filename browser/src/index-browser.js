const createModule = require('../../src/bls_c.js')
const blsSetupFactory = require('../../src/bls.js')
const crypto = window.crypto || window.msCrypto

const getRandomValues = x => crypto.getRandomValues(x)
const bls = blsSetupFactory(createModule, getRandomValues)

module.exports = bls

