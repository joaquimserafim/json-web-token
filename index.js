var crypto = require('crypto');
var b64url = require('base64-url');

// Utilities class
var utils = {};

utils.sign = function (alg, key, input, cb) {
  var op;

  if('hmac' === alg.type) {
    op = b64url.escape(crypto.createHmac(alg.hash, key).update(input).digest('base64'));
    return cb(null, op);
  }

  if('sign' === alg.type) {
    op = b64url.escape(crypto.createSign(alg.hash).update(input).sign(key, 'base64'));
    return cb(null, op);
  }

 return cb(new Error('The algorithm type isn\'t recognized!'));
};

utils.verify = function (alg, key, input, sign, cb) {
  if ('hmac' === alg.type) {
    return this.sign(alg, key, input, function (err, res) {
      if (err) return cb(err);
      cb(null, sign === res);
    });
  }

  if ('sign' === alg.type) {
    var op = crypto.createVerify(alg.hash)
            .update(input)
            .verify(key, b64url.unescape(sign), 'base64');
    return cb(null, op);
  }

  return cb(new Error('The algorithm type isn\'t recognized!'));
};


// JSON Web Token
var jwt = exports;

jwt._algorithms = {
  HS256: {hash: 'sha256', type: 'hmac'},
  HS384: {hash: 'sha384', type: 'hmac'},
  HS512: {hash: 'sha512', type: 'hmac'},
  RS256: {hash: 'RSA-SHA256', type: 'sign'}
};

jwt._search = function (alg) {
  return this._algorithms[alg];
};

jwt.getAlgorithms = function () {
  return Object.keys(this._algorithms);
};

jwt.encode = function (key, payload, algorithm, cb) {
  // some verifications
  if (!key || !payload) return cb(new Error('The key and payload are mandatory!'));

  if (typeof algorithm === 'function') {
    cb = algorithm;
    algorithm = 'HS256';
  }

  if (typeof cb !== 'function') cb = function () {};

  // JWT header
  var header = JSON.stringify({typ: 'JWT', alg: algorithm});

  // get algorithm hash and type and check if is valid
  algorithm = this._search(algorithm);
  if (!algorithm) return cb(new Error('The algorithm is not supported!'));

  var parts = b64url.encode(header) + '.' + b64url.encode(JSON.stringify(payload));

  utils.sign(algorithm, key, parts, function (err, res) {
    if (err) return cb(err);
    cb (null, parts + '.' + res);
  });
};

jwt.decode = function (key, token, cb) {
  // some verifications
  if (!key || !token) return cb(new Error('The key and token are mandatory!'));

  if (typeof cb !== 'function') cb = function () {};

  var parts = token.split('.');
  // check all parts are present
  if (parts.length !== 3) return cb(new Error('The JWT consist of three parts!'));

  // base64 decode and parse JSON
  var header = JSON.parse(b64url.decode(parts[0]));
  var payload = JSON.parse(b64url.decode(parts[1]));

  // get algorithm hash and type and check if is valid
  var algorithm = this._search(header.alg);
  if (!algorithm) return cb(new Error('The algorithm is not supported!'));

  // verify the signature
  utils.verify(algorithm,
                key,
                parts.slice(0, 2).join('.'),
                parts[2],
                function (err, res) {
                  // error or the signature isn't valid
                  if (err || !res)
                    return cb(err || new Error('The JSON Web Signature isn\'t valid!'));
                  // ok, pass the playload
                  cb(null, payload);
                });
};
