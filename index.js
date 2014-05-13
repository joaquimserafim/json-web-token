var crypto = require('crypto');
var base64url = require('base64-url');


var utils = {};

utils.sign = function sign (type, input, key, method) {
  if ('hmac' === type)
    return base64url.escape(crypto.createHmac(method, key).update(input).digest('base64'));

  if ('sign' === type)
    return base64url.escape(crypto.createSign(method).update(input).sign(key, 'base64'));
};

utils.verify = function verify (type, input, key, method, signature) {
  if ('hmac' === type)
    return {res: signature === this.sign(type, input, key, method)};

  if ('sign' === type)
    return {
      res: crypto.createVerify(method)
            .update(input)
            .verify(key, base64url.unescape(signature), 'base64')
   };

  return {error: 'The algorithm type isn\'t recognized!'};
};


var jwt = exports;

jwt._algorithms = {
  'sha256': 'hmac',
  'sha384': 'hmac',
  'sha512': 'hmac',
  'RSA-SHA256': 'sign'
};

jwt._search = function _search (alg) {
  return this._algorithms[alg] && {alg: alg, type: this._algorithms[alg]};
};

jwt.getAlgorithms = function getAlgorithms() {
  return Object.keys(this._algorithms);
};

jwt.encode = function encode (payload, key, algorithm, cb) {
  if (!key) return cb(new Error('Must provide a key/secret!'));

  algorithm = this._search(algorithm) || this._search('sha256');

};

