'use strict'

/**
 * Access Token Exchange with Okta Token Vault
 * 
 * This library implements the access token exchange flow that allows the proxy
 * to exchange an Auth0 access token for an external provider's access token.
 * 
 * @see https://auth0.com/docs/secure/call-apis-on-users-behalf/token-vault/access-token-exchange-with-token-vault
 */


const axios = require('axios')
const oktaAuth0 = require('./okta_auth0_exchange')
const crypto = require('crypto')
const sessionCache = require('./connected_account_session_cache')

// Constants for the token exchange

// Constants for the token exchange
const GRANT_TYPE = 'urn:auth0:params:oauth:grant-type:token-exchange:federated-connection-access-token'
const SUBJECT_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token'
const REQUESTED_TOKEN_TYPE = 'http://auth0.com/oauth/token-type/federated-connection-access-token'

async function exchangeOktaAccessToken(domain, subjectToken, cteClientId, cteClientSecret, vaultClientId, vaultClientSecret, vaultAudience, vaultScope, connection, loginHint) {
  // Validate required parameters

  let auth0Token = ''
  //First we need to perform a token exchange on the inbound token to get an Auth0 token!
  try {
    auth0Token = await oktaAuth0.getAuth0VaultTokenFromOktaToken(domain, subjectToken, cteClientId, cteClientSecret, vaultScope, vaultAudience, connection)
  }
  catch(err) {
    console.log('Unable to obtain an Auth0 token for this user. Please check your configuration within Auth0.')
    console.log(err)
    throw new Error(`Token exchange request failed: ${err.message}`)
  }
  
  if(!auth0Token) {
    return null
  }


  // Build the token exchange request body
  const requestBody = {
    client_id: vaultClientId,
    client_secret: vaultClientSecret,
    subject_token: auth0Token,
    grant_type: GRANT_TYPE,
    subject_token_type: SUBJECT_TOKEN_TYPE,
    requested_token_type: REQUESTED_TOKEN_TYPE,
    connection: connection
  }
  console.log("Making vault request:")
  console.log(requestBody)
  // Add optional login_hint if provided
  // Use login_hint when the user has multiple accounts from the same connection
  // (e.g., work and personal Google accounts)
  if (loginHint) {
    requestBody.login_hint = loginHint
  }

  const tokenUrl = `https://${domain}/oauth/token`

  try {
    const response = await axios.post(tokenUrl, requestBody, {
      headers: {
        'Content-Type': 'application/json'
      }
    })
    console.log("Response from Vault:")
    console.log(response.data)

    return {
      success: true,
      needsLinking: false,
      message: 'Token retrieved successfully!',
      accessToken: response.data.access_token
    }

  } catch (error) {
    if (error.response) {
      // Auth0 returned an error response
      const errorData = error.response.data
      
      // Check for federated_connection_refresh_token_not_found error
      if (error.response.status === 401 && errorData.error === 'federated_connection_refresh_token_not_found') {
        return {
          success: false,
          needsLinking: true,
          accessToken: null,
          message: 'No credentials found in the vault.'
        }
      }
      
      //Some other auth0 error.
      return {
          success: false,
          needsLinking: false,
          accessToken: null,
          message: errorData.error
      }
    } else if (error.request) {
      // Request was made but no response received
      return {
          success: false,
          needsLinking: false,
          accessToken: null,
          message: 'Token exchange request failed: No response received'
    }
    } else {
      // Error setting up the request
            return {
          success: false,
          needsLinking: false,
          accessToken: null,
          message: `Token exchange request failed: ${error.message}`
      }
    }
  }
}



/**
 * Initiates a Connected Accounts flow to link an external provider account.
 * 
 * This function starts the Connected Accounts flow by making a POST request to
 * the My Account API's /me/v1/connected-accounts/connect endpoint.
 * 
 * @param {string} domain - The Auth0 domain (e.g., 'your-tenant.auth0.com')
 * @param {string} subjectToken - The Okta access token to exchange
 * @param {string} cteClientId - The CTE Client ID for token exchange
 * @param {string} cteClientSecret - The CTE Client secret for token exchange
 * @param {string} vaultClientId - The Vault Client ID (unused in this flow but kept for consistency)
 * @param {string} vaultClientSecret - The Vault Client secret (unused in this flow but kept for consistency)
 * @param {string} vaultAudience - The audience for the vault token
 * @param {string} vaultScope - The scope for the vault token
 * @param {string} connection - The connection name (e.g., 'google-oauth2')
 * @param {string} redirectUri - The callback URL of your client application
 * @param {string[]} scopes - The scopes to request from the external provider
 * @returns {Promise<Object>} - Object containing the connect URL and auth_session for later verification
 * 
 * @see https://auth0.com/docs/secure/call-apis-on-users-behalf/token-vault/connected-accounts-for-token-vault#initiate-connected-accounts-request
 */
async function beginConnectedAccountFlow(domain, subjectToken, cteClientId, cteClientSecret, oidcState, connection, completeRedirectUri, externalScopes) {
  let auth0Token = ''
  //First we need to perform a token exchange on the inbound token to get an Auth0 token!
  try {
    console.log("Obtaining an account linking token from Auth0!")
    auth0Token = await oktaAuth0.getAuth0ConnectedAcctTokenFromOktaToken(domain, subjectToken, cteClientId, cteClientSecret, connection)
    console.log(`Token from Auth0 for account linking: ${auth0Token}`)

  }
  catch(err) {
    console.log('Unable to obtain an Auth0 token for this user. Please check your configuration within Auth0.')
    console.log(err)
    throw new Error(`Token exchange request failed: ${err.message}`)
  }
  
  // Generate a random state value for CSRF protection
  const state = crypto.randomBytes(32).toString('base64url')

  // Build the request body for the connected accounts connect endpoint
  // If we find a scope called "refresh_token" replace it with offline access when we send it.
  const finalScopes = externalScopes.join(" ").replace("refresh_token", "offline_access").split(" ")
  const requestBody = {
    connection: connection,
    redirect_uri: completeRedirectUri,
    state: state,
    scopes: finalScopes
  }
  console.log("Connected accounts request")
  console.log(requestBody)
  const connectUrl = `https://${domain}/me/v1/connected-accounts/connect`

  try {
    const response = await axios.post(connectUrl, requestBody, {
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${auth0Token}`
      }
    })

    console.log("Response from Connected Accounts connect endpoint:")
    console.log(response.data)

    // Extract the connect_uri and ticket from the response
    const { auth_session, connect_uri, connect_params } = response.data

    // Build the full URL with the ticket as a query parameter
    const fullConnectUrl = `${connect_uri}?ticket=${connect_params.ticket}`

    // Cache the auth_session and state for the subsequent callback request
    sessionCache.cacheAuthSession(state, oidcState, auth_session, auth0Token)

    return {
      success: true,
      connectUrl: fullConnectUrl,
      authSession: auth_session,
      state: state,
      message: 'Connected account flow initiated successfully'
    }

  } catch (error) {
    if (error.response) {
      // Auth0 returned an error response
      const errorData = error.response.data
      console.log('Error from Connected Accounts connect endpoint:', errorData)
      
      return {
        success: false,
        connectUrl: null,
        authSession: null,
        message: errorData.error_description || errorData.error || 'Failed to initiate connected account flow'
      }
    } else if (error.request) {
      // Request was made but no response received
      return {
        success: false,
        connectUrl: null,
        authSession: null,
        message: 'Connected accounts request failed: No response received'
      }
    } else {
      // Error setting up the request
      return {
        success: false,
        connectUrl: null,
        authSession: null,
        message: `Connected accounts request failed: ${error.message}`
      }
    }
  }
}

// Export the module functions
module.exports = {
  exchangeOktaAccessToken,
  beginConnectedAccountFlow,
  getCachedAuthSession: sessionCache.getCachedAuthSession,
  clearCachedAuthSession: sessionCache.clearCachedAuthSession
}
