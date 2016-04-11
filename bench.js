'use strict'

const Benchmark = require('benchmark')
const jwt = require('./')

const payload = {
  iss: 'my_issurer',
  aud: 'World',
  iat: new Date().getTime(),
  typ: '/online/transactionstatus/v2',
  request: {
    myTransactionId: uuid(),
    merchantTransactionId: uuid(),
    status: 'SUCCESS'
  }
}

const secret = 'TOPSECRETTTTT'
var holdToken

console.log('starting `json-web-token` benchmark')

new Benchmark.Suite()
  .add('json-web-token#encode', () => {
    jwt.encode(secret, payload, (err, token) => {
      if (err) {
        throw err
      }

      holdToken = token
    })
  })
  .add('json-web-token#decode', () => {
    jwt.decode(secret, holdToken, (err, decoded) => {
      if (err) {
        throw err
      }
    })
  })
  .on('cycle', (event) => {
    console.log(String(event.target))
  })
  .on('complete', () => {
    console.log('benchmark finish')
  })
  .run({'async': true})

//
//
//

function uuid () {
  return (~~(Math.random() * 1e9)).toString(36)
}

