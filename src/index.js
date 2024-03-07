const createModule = require('./bls_c.js')
const blsSetupFactory = require('./bls')

const bls = blsSetupFactory(createModule)

module.exports = bls
