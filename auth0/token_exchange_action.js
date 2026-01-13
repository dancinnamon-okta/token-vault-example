/**
* Handler to be executed while executing a custom token exchange request
* @param {Event} event - Details about the incoming token exchange request.
* @param {CustomTokenExchangeAPI} api - Methods and utilities to define token exchange process.
*/
exports.onExecuteCustomTokenExchange = async (event, api) => {
  // Code goes here
  const jwt = require('jsonwebtoken');
  const jwksClient = require('jwks-rsa');
  const jwksUri = event.secrets.TRUSTED_JWKS//"https://yourenvironment.okta.com/oauth2/authzserverid/v1/keys"

  const jwtValidatorOptions = {
      'complete': true,
      'issuer': event.secrets.TRUSTED_ISSUER//"https://yourenvironment.okta.com/oauth2/authzserverid",
  };

  function validateToken(subjectToken) {
    var client = jwksClient({
      jwksUri: jwksUri
    });
    function getKey(header, callback){
      client.getSigningKey(header.kid, function(err, key) {
        var signingKey = key.publicKey || key.rsaPublicKey;
        callback(null, signingKey);
      });
    }

    let promise = new Promise(function(resolve, reject) {
      jwt.verify(subjectToken, getKey, jwtValidatorOptions, function(err, decoded) {
        if(err) {
          reject(false)
        }
        else {
          console.log('Inbound token validated!')
          resolve(decoded)
        }
      });
    });
    return promise
  }

  const decodedResult = await validateToken(event.transaction.subject_token)
  if(!decodedResult) {
    api.access.rejectInvalidSubjectToken("The provided subject token was not valid.")
  }
  else {
    console.log("Valid token contents:")
    console.log(decodedResult)

    console.log(`Making connection using user_id: ${decodedResult.payload.uid}`)
    api.authentication.setUserByConnection(
      'AI-Users-From-Okta',
      {
        user_id: decodedResult.payload.uid,
        username: decodedResult.payload.sub
      },
      {
        creationBehavior: 'create_if_not_exists',
        updateBehavior: 'none'
      }
    );
    
  }
  return;
};