const axios = require('axios');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const crypto = require('crypto');

/**
 * Generates a client assertion JWT for private_key_jwt authentication
 * @param {string} clientId - The client ID (used as iss and sub claims)
 * @param {string} tokenEndpoint - The token endpoint URL (used as audience)
 * @param {string} privateKeyPath - Path to the private key file
 * @returns {string} - The signed JWT assertion
 */
function generateClientAssertion(clientId, tokenEndpoint, privateKeyPath, kid) {
  const privateKey = fs.readFileSync(privateKeyPath, 'utf8');
  
  const now = Math.floor(Date.now() / 1000);
  const jti = crypto.randomUUID();
  
  const payload = {
    iss: clientId,
    sub: clientId,
    aud: tokenEndpoint,
    iat: now,
    exp: now + 300, // 5 minutes expiry
    jti: jti
  };
  
  return jwt.sign(payload, privateKey, { algorithm: 'RS256', keyid: kid });
}

/**
 * Exchanges credentials for an access token from Auth0
 * @param {string} auth0Domain - The Auth0 domain (e.g., 'your-tenant.auth0.com')
 * @param {string} accessToken - The access token to exchange
 * @param {string} clientId - The Auth0 client ID
 * @param {string} clientSecret - The Auth0 client secret
 * @returns {Promise<object>} - The token response from Auth0
 */
async function getAuth0VaultTokenFromOktaToken(auth0Domain, accessToken, clientId, clientSecret, scope, audience, connection) {
    return getExchangedAuth0Token(auth0Domain, accessToken, clientId, clientSecret, scope, audience, connection)
}

async function getAuth0ConnectedAcctTokenFromOktaToken(auth0Domain, accessToken, clientId, clientSecret, connection) {
    const connectedAccountScope = 'create:me:connected_accounts read:me:connected_accounts delete:me:connected_accounts'
    const connectedAccountAudience = `https://${auth0Domain}/me/`
    return getExchangedAuth0Token(auth0Domain, accessToken, clientId, clientSecret, connectedAccountScope, connectedAccountAudience, connection)
}

async function getExchangedAuth0Token(auth0Domain, accessToken, clientId, clientSecret, scope, audience, connection) {
    const tokenUrl = `https://${auth0Domain}/oauth/token`;

    const subjectTokenType = `https://danc-ai-beta/gateway/${connection}`

    const response = await axios.post(tokenUrl, {
        grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
        subject_token: accessToken,
        subject_token_type: subjectTokenType,
        client_id: clientId,
        client_secret: clientSecret,
        audience: audience,
        scope: scope
    }, {
        headers: {
            'Content-Type': 'application/json'
        }
    });
    return response.data.access_token
}

async function getAuth0ConnectedAcctClientCredentialsToken(auth0Domain, clientId, clientSecret, scope, audience) {
    const tokenUrl = `https://${auth0Domain}/oauth/token`;

    const response = await axios.post(tokenUrl, {
        grant_type: 'client_credentials',
        client_id: clientId,
        client_secret: clientSecret,
        audience: audience,
        scope: scope
    }, {
        headers: {
            'Content-Type': 'application/json'
        }
    });
    return response.data.access_token
}

//This is the method that will simply complete the Okta login and get ID token for the user.
//We'll then use that ID token to get a JAG.
async function completeOktaOIDCLogin(tokenEndpoint, code, redirectUri, scope, client_id, client_secret) {
    
    // Build the token request body
    const tokenRequestBody = new URLSearchParams()
    tokenRequestBody.set('grant_type', 'authorization_code')
    tokenRequestBody.set('code', code)
    tokenRequestBody.set('redirect_uri', redirectUri)
    tokenRequestBody.set('client_id', client_id) //process.env.PROXY_CLIENT_ID
    tokenRequestBody.set('client_secret', client_secret)
    tokenRequestBody.set('scope', scope)

    console.log(`Exchanging authorization code for tokens at: ${tokenEndpoint}`)

    const response = await axios.post(tokenEndpoint, tokenRequestBody.toString(), {
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
    })
    console.log('Token exchange successful')
    return response.data.id_token
}

/**
 * Exchanges credentials for an access token from Auth0
 * @param {string} tenantConfig - The configuration of the tenant in question- determines our audience, scopes, etc.
 * @param {string} idToken - The Okta id token we're exchanging for a JAG.
 * @param {string} clientId - The client id of our workload principal/agent.
 * @param {string} clientSecretKeyFile - The private keyfile path of our workload principal/agent.
 * @returns {Promise<object>} - The ID JAG from Okta as a response.
 */
async function getIdJagFromOkta(tokenEndpoint, tenantConfig, idToken, clientId, clientSecretKeyFile, kid) {
  // Validate required parameters
  if (!tenantConfig) {
    throw new Error('tenantConfig is required')
  }

  if (!idToken) {
    throw new Error('idJag (Identity Assertion JWT Authorization Grant) is required')
  }

  // Build the token request body per Section 4.4 of the ID-JAG spec
  const requestBody = new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
    requested_token_type: 'urn:ietf:params:oauth:token-type:id-jag',
    audience: tenantConfig.issuer,
    scope: tenantConfig.external_scopes.join(" "),
    subject_token_type: 'urn:ietf:params:oauth:token-type:id_token',
    subject_token: idToken
  })

  // Build request headers
  const headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Accept': 'application/json'
  }

  // Add client authentication using private_key_jwt

  const clientAssertion = generateClientAssertion(clientId, tokenEndpoint, clientSecretKeyFile, kid)
  requestBody.append('client_id', clientId)
  requestBody.append('client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer')
  requestBody.append('client_assertion', clientAssertion)


  console.log(`ID-JAG Exchange: Requesting access token from ${tokenEndpoint}`)
  console.log(`Request: ${requestBody.toString()}`)

  try {
    const response = await axios.post(tokenEndpoint, requestBody.toString(), {
      headers
    })

    console.log('ID-JAG Exchange: Successfully obtained ID JAG token')
    console.log(response.data)
    return response.data.access_token
  } catch (error) {
    // Handle OAuth error responses
    if (error.response && error.response.data) {
      const errorData = error.response.data
      console.error('ID-JAG Exchange failed:', errorData)
      
      const errorMessage = errorData.error_description || errorData.error || 'Unknown error'
      throw new Error(`ID-JAG exchange failed: ${errorMessage}`)
    }
    
    console.error('ID-JAG Exchange request failed:', error.message)
    throw new Error(`ID-JAG exchange request failed: ${error.message}`)
  }
}

/**
 * Exchanges credentials for an access token from Auth0
 * @param {string} tenantConfig - The configuration of the tenant in question- determines our audience, scopes, etc.
 * @param {string} idToken - The Okta id token we're exchanging for a JAG.
 * @param {string} clientId - The client id of our workload principal/agent.
 * @returns {Promise<object>} - The ID JAG from Okta as a response.
 */
async function getAccessTokenFromIDJag(tenantConfig, idJagToken, clientId, clientSecretKeyFile, kid) {
  // Validate required parameters
  if (!tenantConfig) {
    throw new Error('tenantConfig is required')
  }

  if (!idJagToken) {
    throw new Error('idJag (Identity Assertion JWT Authorization Grant) is required')
  }

  const tokenEndpoint = `${tenantConfig.issuer}/v1/token`
  const clientAssertion = generateClientAssertion(clientId, tokenEndpoint, clientSecretKeyFile, kid)

  // Build the token request body per Section 4.4 of the ID-JAG spec
  const requestBody = new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    assertion: idJagToken,
    client_id: clientId,
    client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    client_assertion: clientAssertion
  })

  // Build request headers
  const headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Accept': 'application/json'
  }

  console.log(`ID-JAG Access Exchange: Requesting access token from ${tokenEndpoint}`)
  console.log(`Request: ${requestBody.toString()}`)

  try {
    const response = await axios.post(tokenEndpoint, requestBody.toString(), {
      headers
    })

    console.log('ID-JAG Access Exchange: Successfully obtained access token')
    console.log(response.data)

    return response.data.access_token
  } catch (error) {
    // Handle OAuth error responses
    if (error.response && error.response.data) {
      const errorData = error.response.data
      console.error('ID-JAG Access Exchange failed:', errorData)
      
      const errorMessage = errorData.error_description || errorData.error || 'Unknown error'
      throw new Error(`ID-JAG Access exchange failed: ${errorMessage}`)
    }
    
    console.error('ID-JAG Access Exchange request failed:', error.message)
    throw new Error(`ID-JAG Access exchange request failed: ${error.message}`)
  }
}

module.exports = {
    getAuth0VaultTokenFromOktaToken,
    getAuth0ConnectedAcctTokenFromOktaToken,
    getAuth0ConnectedAcctClientCredentialsToken,
    completeOktaOIDCLogin,
    getIdJagFromOkta,
    getAccessTokenFromIDJag
};
