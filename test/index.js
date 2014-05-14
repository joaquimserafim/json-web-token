var jwt = require('../');

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
  if (err) return console.error(err);
  console.log(token);
  console.log();

  jwt.decode(secret, token, function (err_, res) {

    console.log('DECODE');
    if (err_) return console.error(err_);
    console.log(res);
  });
});


