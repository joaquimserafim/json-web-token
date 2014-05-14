# json-web-token





**More info**

<a href="https://nodei.co/npm/json-web-token/"><img src="https://nodei.co/npm/json-web-token.png?downloads=true"></a>

[![Build Status](https://travis-ci.org/joaquimserafim/json-web-token.png?branch=master)](https://travis-ci.org/joaquimserafim/json-web-token)



**V1**




###API
  
  
#####  jwt#encode(key, payload, [algorithm], cb)
  
* **key**, your secret
* **payload**, the payload or Claim Names, 

	ex:
	
		{
		  "iss": "my_issurer",
		  "aud": "World",
		  "iat": 1400062400223,
		  "typ": "/online/transactionstatus/v2",
		  "request": {
		    "myTransactionId": "[myTransactionId]",
		    "merchantTransactionId": "[merchantTransactionId]",
		    "status": "SUCCESS"
		  }
		}

	*attention that exists some reserved claim names (like "iss", "iat", etc..) check [in here](http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-08#section-4) for more info about JWT Claims.*	
* **algorithm**, default to 'sha256', use jwt#getAlgorithms()to get the supported algorithms
* **cb**, the callback(err, token)


#####  jwt#decode(key, token, validateJWT, cb)

* **key**, your secret
* **token**


