const createModule = require('./bls_c.js')
const blsSetupFactory = require('./bls')
const crypto = require('crypto')

const getRandomValues = crypto.randomFillSync
const bls = blsSetupFactory(createModule, getRandomValues)

module.exports = bls
