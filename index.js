'use strict';

var crypto    = require('crypto');
var b64url    = require('base64-url');
var inherits  = require('util').inherits;

//
// JWT token error
//
function JWTError(message) {
  Error.call(this);
  Error.captureStackTrace(this, this.constructor);
  this.name = this.constructor.name;
  this.message = message;
}

inherits(JWTError, Error);

//
// Utilities class
//
var utils = {};

utils.sign = function sign(alg, key, input) {
  if ('hmac' === alg.type) {
    return b64url.escape(crypto.createHmac(alg.hash, key)
      .update(input)
      .digest('base64'));
  } else {// ('sign' === alg.type)
    return b64url.escape(crypto.createSign(alg.hash)
      .update(input)
      .sign(key, 'base64'));
  }
};

utils.verify = function verify(alg, key, input, sign) {
  if ('hmac' === alg.type) {
    return sign === this.sign(alg, key, input);
  } else {// ('sign' === alg.type)
    return crypto.createVerify(alg.hash)
      .update(input)
      .verify(key, b64url.unescape(sign), 'base64');
  }
};

utils.fnError = function(err, cb) {
  return cb ?
    cb(err) :
    {error: err};
};

utils.fnResult = function(res, cb) {
  return cb ?
    cb(undefined, res) :
    {value: res};
};

//
// JSON Web Token
//
var jwt = module.exports;

jwt.JWTError = JWTError;

jwt._algorithms = {
  HS256: {hash: 'sha256', type: 'hmac'},
  HS384: {hash: 'sha384', type: 'hmac'},
  HS512: {hash: 'sha512', type: 'hmac'},
  RS256: {hash: 'RSA-SHA256', type: 'sign'}
};

jwt._search = function _search(alg) {
  return this._algorithms[alg];
};

jwt.getAlgorithms = function getAlgorithms() {
  return Object.keys(this._algorithms);
};

jwt.encode = function encode(key, payload, algorithm, cb) {
  //
  // some verifications
  //
  if (!algorithm || typeof algorithm === 'function') {
    cb = algorithm;
    algorithm = 'HS256';
  }

  // verify key & payload
  if (!key || !payload) {
    return utils.fnError(
      new JWTError('The key and payload are mandatory!'), cb
    );
  } else if (!Object.keys(payload).length) {
    return utils.fnError(new JWTError('The payload is empty object!'), cb);
  } else {
    // JWT header
    var header = JSON.stringify({typ: 'JWT', alg: algorithm});

    // get algorithm hash and type and check if is valid
    algorithm = this._search(algorithm);

    if (algorithm) {
      var parts = b64url.encode(header) +
        '.' + b64url.encode(JSON.stringify(payload));
      var res = utils.sign(algorithm, key, parts);
      return utils.fnResult(parts + '.' + res, cb);
    } else {
      return utils.fnError(
        new JWTError('The algorithm is not supported!'), cb
      );
    }
  }
};

jwt.decode = function decode(key, token, cb) {
  if (!key || !token) {
    return utils.fnError(new JWTError('The key and token are mandatory!'), cb);
  } else {
    var parts = token.split('.');

    // check all parts're present
    if (parts.length !== 3) {
      return utils.fnError(
        new JWTError('The JWT should consist of three parts!'), cb
      );
    }

    // base64 decode and parse JSON
    var header = JSON.parse(b64url.decode(parts[0]));
    var payload = JSON.parse(b64url.decode(parts[1]));

    // get algorithm hash and type and check if is valid
    var algorithm = this._search(header.alg);

    if (!algorithm) {
      return utils.fnError(
        new JWTError('The algorithm is not supported!'), cb
      );
    } else {
      // verify the signature
      var res = utils.verify(
        algorithm,
        key,
        parts.slice(0, 2).join('.'),
        parts[2]
      );

      if (res) {
        return utils.fnResult(payload, cb);
      } else {
        return utils.fnError(new JWTError('Invalid key!'), cb);
      }
    }
  }
};
