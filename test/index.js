'use strict'

const read = require('fs').readFileSync
const b64url = require('base64-url')
const path = require('path')
const assert = require('assert')
const { suite, test } = require('mocha')

const jwt = require('../index')

const payload = {
  iss: 'my_issurer',
  aud: 'World',
  iat: 1400062400223,
  typ: '/online/transactionstatus/v2',
  request: {
    myTransactionId: '[myTransactionId]',
    merchantTransactionId: '[merchantTransactionId]',
    status: 'SUCCESS'
  }
}

const secret = 'TOPSECRETTTTT'
let theToken = null
let theTokenSign = null
let theTokenSignWithHeaders = null
let algorithms

suite('json-web-token', function () {
  test('get the error class', function () {
    var JWTError = jwt.JWTError
    assert.strictEqual(typeof JWTError, 'function')
    assert.ok((new JWTError()) instanceof Error)
  })

  test('get the jwt supported algorithms', function () {
    algorithms = jwt.getAlgorithms()
    assert.deepStrictEqual(typeof algorithms, 'object')
    assert.ok(Object.keys(algorithms).length)
  })

  test('jwt - encode with callback / hmac', function () {
    jwt.encode(secret, payload, function (err, token) {
      assert.deepStrictEqual(err, null)
      assert.ok(token)
      assert.deepStrictEqual(token.split('.').length, 3)
      theToken = token
    })
  })

  test('jwt - encode with callback / sign', function () {
    var pem = read(path.join(__dirname, '/fixtures/test.pem')).toString('ascii')
    jwt.encode(pem, payload, 'RS256', function (err, token) {
      assert.deepStrictEqual(err, null)
      assert.ok(token)
      theTokenSign = token
      assert.deepStrictEqual(token.split('.').length, 3)
    })
  })

  test('jwt - encode with callback / bad algorithm', function (done) {
    jwt.encode(secret, payload, 'wow', function (err) {
      assert.deepStrictEqual(err.message, 'The algorithm is not supported!')
      done()
    })
  })

  test('jwt - decode with callback / hmac', function (done) {
    jwt.decode(secret, theToken, function (err, decodePayload) {
      assert.deepStrictEqual(err, null)
      assert.deepStrictEqual(decodePayload, payload)
      done()
    })
  })

  test('jwt - decode with callback / sign', function (done) {
    var crt = read(path.join(__dirname, '/fixtures/test.crt')).toString('ascii')
    jwt.decode(crt, theTokenSign, function (err, decodePayload) {
      assert.deepStrictEqual(err, null)
      assert.deepStrictEqual(decodePayload, payload)
      done()
    })
  })

  test('jwt + custom headers - encode with callback / sign', function (done) {
    var pem = read(path.join(__dirname, '/fixtures/test.pem')).toString('ascii')
    var payloadAndHeaders = {
      payload: payload,
      header: {
        kid: 'TestKeyId'
      }
    }

    jwt.encode(pem, payloadAndHeaders, 'RS256', function (err, token) {
      assert.deepStrictEqual(err, null)
      assert.ok(token)
      theTokenSignWithHeaders = token
      assert.deepStrictEqual(token.split('.').length, 3)
      done()
    })
  })

  test('jwt + custom headers - decode with callback / sign', function (done) {
    var crt = read(path.join(__dirname, '/fixtures/test.crt')).toString('ascii')
    jwt.decode(crt, theTokenSignWithHeaders, function (err, decPayload, header) {
      assert.deepStrictEqual(err, null)
      assert.deepStrictEqual(decPayload, payload)
      assert.deepStrictEqual(header.kid, 'TestKeyId')
      done()
    })
  })

  test('jwt - decode with callback / bad algorithm', function (done) {
    var t = theToken.split('.').slice(1, 3)
    var badHeader = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJ3b3cifQ'
    t = badHeader + '.' + t.join('.')
    jwt.decode(secret, t, function (err) {
      assert.strictEqual(err.name, 'JWTError')
      assert.strictEqual(err.message, 'The algorithm is not supported!')
      done()
    })
  })

  test('jwt - decode with callback / bad token', function (done) {
    var badToken = theToken.split('.')
    badToken[1] = 'bad token hash'
    jwt.decode(secret, badToken.join('.'), function (err) {
      assert.strictEqual(err.name, 'JWTError')
      assert.strictEqual(err.message, 'Invalid key!')
      done()
    })
  })

  test('jwt - decode with callback / invalid key', function (done) {
    jwt.decode('wow', theToken, function (err) {
      assert.strictEqual(err.name, 'JWTError')
      assert.strictEqual(err.message, 'Invalid key!')
      done()
    })
  })

  test('jwt - encode with callback / null payload', function (done) {
    jwt.encode(secret, null, function (err) {
      assert.strictEqual(err.name, 'JWTError')
      assert.strictEqual(err.message, 'The key and payload are mandatory!')
      done()
    })
  })

  test('jwt - encode with callback / empty payload', function (done) {
    jwt.encode(secret, {}, function (err) {
      assert.strictEqual(err.name, 'JWTError')
      assert.strictEqual(err.message, 'The payload is an empty object!')
      done()
    })
  })

  test('jwt - encode with callback / null secret', function (done) {
    jwt.encode(null, payload, function (err) {
      assert.strictEqual(err.name, 'JWTError')
      assert.strictEqual(err.message, 'The key and payload are mandatory!')
      done()
    })
  })

  test('jwt - decode with callback / null key', function (done) {
    jwt.decode(null, theToken, function (err) {
      assert.strictEqual(err.name, 'JWTError')
      assert.strictEqual(err.message, 'The key and token are mandatory!')
      done()
    })
  })

  test('jwt - decode with callback / bad token', function (done) {
    jwt.decode(secret, theToken.split('.').slice(0, 2).join('.'), function (err) {
      assert.strictEqual(err.name, 'JWTError')
      assert.strictEqual(err.message, 'The JWT should consist of three parts!')
      done()
    })
  })

  //
  // without callback but returning the result
  //

  test('jwt - encode without callback / hmac', function () {
    var res = jwt.encode(secret, payload)
    assert.deepStrictEqual(typeof res, 'object')
    assert.deepStrictEqual(res.error, null)
    assert.ok(res.value)
    assert.deepStrictEqual(res.value.split('.').length, 3)
  })

  test('jwt - decode without callback / hmac', function () {
    var res = jwt.decode(secret, theToken)
    assert.deepStrictEqual(typeof res, 'object')
    assert.deepStrictEqual(res.error, null)
    assert.deepStrictEqual(res.value, payload)
  })

  test('jwt - encode without callback / null payload', function () {
    var res = jwt.encode(secret, null)
    assert.deepStrictEqual(typeof res, 'object')
    assert.strictEqual(res.error.name, 'JWTError')
    assert.strictEqual(res.error.message, 'The key and payload are mandatory!')
  })

  test('jwt - encode without callback / empty payload', function () {
    var res = jwt.encode(secret, {})
    assert.deepStrictEqual(typeof res, 'object')
    assert.strictEqual(res.error.name, 'JWTError')
    assert.strictEqual(res.error.message, 'The payload is an empty object!')
  })

  test('jwt - encode without callback / null secret', function () {
    var res = jwt.encode(null, payload)
    assert.deepStrictEqual(typeof res, 'object')
    assert.strictEqual(res.error.name, 'JWTError')
    assert.strictEqual(res.error.message, 'The key and payload are mandatory!')
  })

  //
  // test the jwt vulnerability because of the "none" algorithm
  // this alg is intended to be used for situations where the integrity
  // of the token has already been verified
  //

  test('should not encode for the "none" algorithm - 1', function (done) {
    jwt.encode(secret, payload, 'none', function (err) {
      assert.strictEqual(err.name, 'JWTError')
      assert.strictEqual(err.message, 'The algorithm is not supported!')
      done()
    })
  })

  test('should not decode for the "none" algorithm - 2', function () {
    var encode = jwt.encode(secret, payload).value
    var badToken = encode.split('.')
    var badAlg = b64url.encode(JSON.stringify({ typ: 'JWT', alg: 'none' }))
    badToken[0] = badAlg
    var result = jwt.decode(secret, badToken.join('.'))
    assert.deepStrictEqual(!!result.error, true)
    assert.strictEqual(result.error.name, 'JWTError')
    assert.strictEqual(result.error.message, 'The algorithm is not supported!')
  })
})
