'use strict';

var crypto = require('crypto');
var b64url = require('base64-url');

//
// Utilities class
//
var utils = {};

utils.sign = function sign(alg, key, input, cb) {
  var op;

  if ('hmac' === alg.type) {
    op = b64url.escape(
      crypto.createHmac(alg.hash, key)
        .update(input)
        .digest('base64')
    );

    cb(null, op);
  } else if ('sign' === alg.type) {
    op = b64url.escape(
      crypto.createSign(alg.hash)
        .update(input)
        .sign(key, 'base64')
    );

    cb(null, op);
  } else {
    cb(new Error('The algorithm type isn\'t recognized!'));
  }
};

utils.verify = function verify(alg, key, input, sign, cb) {
  if ('hmac' === alg.type) {
    this.sign(alg, key, input, function(err, res) {
      if (err) {
        cb(err);
      } else {
        cb(null, sign === res);
      }
    });
  } else if ('sign' === alg.type) {
    var op = crypto.createVerify(alg.hash)
      .update(input)
      .verify(key, b64url.unescape(sign), 'base64');

    cb(null, op);
  } else {
    cb(new Error('The algorithm type isn\'t recognized!'));
  }
};

utils.noop = function noop() {};

//
// JSON Web Token
//
var jwt = module.exports;

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
  // some verifications
  if (!key || !payload) {
    cb(new Error('The key and payload are mandatory!'));
  } else {
    if (typeof algorithm === 'function') {
      cb = algorithm;
      algorithm = 'HS256';
    }

    if (typeof cb !== 'function') {
      cb = utils.noop;
    }

    // JWT header
    var header = JSON.stringify({typ: 'JWT', alg: algorithm});

    // get algorithm hash and type and check if is valid
    algorithm = this._search(algorithm);

    if (!algorithm) {
      cb(new Error('The algorithm is not supported!'));
    } else {
      var parts = b64url.encode(header) +
        '.' + b64url.encode(JSON.stringify(payload));

      utils.sign(algorithm, key, parts, function(err, res) {
        if (err) {
          cb(err);
        } else {
          cb(null, parts + '.' + res);
        }
      });
    }
  }
};

jwt.decode = function decode(key, token, cb) {
  // some verifications
  if (!key || !token) {
    cb(new Error('The key and token are mandatory!'));
  } else {
    if (typeof cb !== 'function') {
      cb = utils.noop;
    }

    var parts = token.split('.');

    // check all parts are present
    if (parts.length !== 3) {
      return cb(new Error('The JWT should consist of three parts!'));
    }

    // base64 decode and parse JSON
    var header = JSON.parse(b64url.decode(parts[0]));
    var payload = JSON.parse(b64url.decode(parts[1]));

    // get algorithm hash and type and check if is valid
    var algorithm = this._search(header.alg);

    if (!algorithm) {
      cb(new Error('The algorithm is not supported!'));
    } else {
      // verify the signature
      utils.verify(
        algorithm,
        key,
        parts.slice(0, 2).join('.'),
        parts[2],
        function(err, res) {
          // error or the signature isn't valid
          if (err || !res) {
            cb(err || new Error('The JSON Web Signature isn\'t valid!'));
          } else {
            // ok, pass the playload
            cb(null, payload);
          }
        }
      );
    }
  }
};
