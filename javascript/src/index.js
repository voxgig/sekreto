// @voxgig/sekreto-js - one interface for secrets, wherever they live.

const providers = require('./Providers')
const sekreto = require('./Sekreto')

module.exports = { ...sekreto, ...providers }
