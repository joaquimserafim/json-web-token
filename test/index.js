var test = require('tape');
var jwt = require('../');


test('timing test', function (t) {
  t.plan(5);

  var payload = {
    "iss": "my_issurer",
    "aud": "World",
    "iat": 1400062400223,
    "typ": "/online/transactionstatus/v2",
    "request": {
      "myTransactionId": "[myTransactionId]",
      "merchantTransactionId": "[merchantTransactionId]",
      "status": "SUCCESS"
    }
  };

  var secret = 'TOPSECRETTTTT';

  // encode
  jwt.encode(secret, payload, function (err, token) {
    t.error(err, 'encode token shouldn\'t return any error');
    t.deepEqual(token.split('.').length, 3, 'a JWT token must be compound by 3 parts or segments - JWT header, JWT payload and JWT crypto');

    jwt.decode(secret, token, function (err_, decode_payload) {
      t.error(err_, 'decode token shouldn\'t return any error');
      t.deepEqual(typeof decode_payload, 'object', 'payload should be an object');
      t.deepEqual(JSON.stringify(decode_payload), JSON.stringify(payload), 'decoded payload should be equal to payload');
    });
  });
});
