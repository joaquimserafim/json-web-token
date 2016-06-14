'use strict'

const crypto    = require('crypto')
const b64url    = require('base64-url')
const inherits  = require('util').inherits
const parse     = require('json-parse-safe')

//
// supported algorithms
//

const algorithms = {
  HS256: {hash: 'sha256', type: 'hmac'},
  HS384: {hash: 'sha384', type: 'hmac'},
  HS512: {hash: 'sha512', type: 'hmac'},
  RS256: {hash: 'RSA-SHA256', type: 'sign'}
}

//
// JSON Web Token
//

const jwt = module.exports

jwt.JWTError      = JWTError
jwt.getAlgorithms = getAlgorithms
jwt.encode        = encode
jwt.decode        = decode

function getAlgorithms () {
  return Object.keys(algorithms)
}

function encode (key, payload, algorithm, cb) {
  if (paramIsValid(algorithm, 'function')) {
    cb = algorithm
    algorithm = 'HS256'
  }

  var validationError = encodeValidations(key, payload, algorithm)

  if (validationError) {
    return prcResult(validationError, null, cb)
  }

  var parts = b64url.encode(JSON.stringify({typ: 'JWT', alg: algorithm})) +
    '.' +
    b64url.encode(JSON.stringify(payload))

  return prcResult(
    null,
    parts + '.' + sign(algorithms[algorithm], key, parts),
    cb
  )
}

function decode (key, token, cb) {
  if (paramsAreFalsy(key, token)) {
    return prcResult('The key and token are mandatory!', null, cb)
  }

  var parts = token.split('.')

  // check all parts're present
  if (parts.length !== 3) {
    return prcResult(
      'The JWT should consist of three parts!',
      null,
      cb
    )
  }

  // base64 decode and parse JSON
  var header = JSONParse(b64url.decode(parts[0]))
  var payload = JSONParse(b64url.decode(parts[1]))

  // get algorithm hash and type and check if is valid
  var algorithm = algorithms[header.alg]

  if (!algorithm) {
    return prcResult('The algorithm is not supported!', null, cb)
  }

  // verify the signature
  var res = verify(
    algorithm,
    key,
    parts.slice(0, 2).join('.'),
    parts[2]
  )

  return prcResult(!res && 'Invalid key!' || null, payload, cb)
}

function encodeValidations (key, payload, algorithm) {
  return paramsAreFalsy(key, payload) ?
    'The key and payload are mandatory!' :
      !Object.keys(payload).length ?
        'The payload is an empty object!' :
        !algorithms[algorithm] && 'The algorithm is not supported!'
}

//
// JWT token error
//

function JWTError (message) {
  Error.call(this)
  Error.captureStackTrace(this, this.constructor)
  this.name = this.constructor.name
  this.message = message
}

inherits(JWTError, Error)

//
// Utils methods
//

function sign (alg, key, input) {
  return 'hmac' === alg.type ?
    b64url.escape(crypto.createHmac(alg.hash, key)
      .update(input)
      .digest('base64')) :
    b64url.escape(crypto.createSign(alg.hash)
      .update(input)
      .sign(key, 'base64'))
}

function verify (alg, key, input, signVar) {
  return 'hmac' === alg.type ?
    signVar === sign(alg, key, input) :
    crypto.createVerify(alg.hash)
      .update(input)
      .verify(key, b64url.unescape(signVar), 'base64')
}

function prcResult (err, res, cb) {
  err = err && new JWTError(err)

  return cb ?
    cb(err, res) :
    {error: err, value: res}
}

function paramIsValid (param, type) {
  return !param || typeof param === type
}

function paramsAreFalsy (param1, param2) {
  return !param1 || !param2
}

function JSONParse (str) {
  var res = parse(str)

  return res.error && '' || res.value
}

