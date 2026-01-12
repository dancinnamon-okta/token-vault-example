'use strict'
const crypto = require('crypto')
const outboundRequestCache = require('../lib/outbound_request_cache')
const oktaAuth0Exchange = require('../lib/okta_auth0_exchange')
const tenantConfig = require('../lib/tenant_config')
const vault = require('../lib/token_vault')
const returningAuthzCache = require("../lib/return_authz_cache")

/**
 * OAuth 2.0 Callback Endpoint
 * 
 * This module handles the callback from the authorization server after
 * the user has authenticated. It validates the state parameter, exchanges
 * the authorization code for tokens, and processes the response.
 */

/**
 * Connects the callback routes to the Express app.
 */
module.exports.connect = function (app) {

    /**
     * GET /callback
     * 
     * Handles the OIDC callback from the authorization server.
     * This endpoint receives the authorization code and state after
     * the user has authenticated with the identity provider.
     * 
     * Query Parameters:
     * - state: The state value that was sent in the authorize request
     * - code: The authorization code to exchange for tokens
     * - error: (optional) Error code if authorization failed
     * - error_description: (optional) Description of the error
     * 
     * The state is used to retrieve the cached outbound request and validate
     * that this callback corresponds to a request we initiated.
     */
    app.get('/callback', async (req, res) => {
        const { state, code, error, error_description } = req.query

        // Handle authorization errors from the IdP
        if (error) {
            console.error(`Authorization error: ${error} - ${error_description}`)
            return res.status(400).json({
                error: error,
                error_description: error_description || 'Authorization failed at the identity provider.'
            })
        }

        // Validate required parameters
        if (!state) {
            return res.status(400).json({
                error: 'invalid_request',
                error_description: 'The state parameter is required.'
            })
        }

        if (!code) {
            return res.status(400).json({
                error: 'invalid_request',
                error_description: 'The code parameter is required.'
            })
        }

        // Retrieve the cached outbound request using the state value
        const cachedRequest = outboundRequestCache.getCachedOutboundRequest(state)

        if (!cachedRequest) {
            return res.status(400).json({
                error: 'invalid_state',
                error_description: 'The state parameter is invalid or has expired. Please restart the authorization flow.'
            })
        }

        //We need a fair bit of detail from the original inbound authz request, get this data from our cache (was inserted on /authorize endpoint)
        const { tenantId, originalState, originalParameters, parameters } = cachedRequest

        // Exchange the authorization code for tokens
        //All we want is openid here- we're just doing a normal login- we haven't touched final resources yet.
        const tokenEndpoint = `${process.env.OKTA_DOMAIN}/oauth2/v1/token`
        const redirectUri = parameters.get("redirect_uri")
        const scope = 'openid'
        const tenant = tenantConfig.getTenantConfig(tenantId)
        try {

            const idToken = await oktaAuth0Exchange.completeOktaOIDCLogin(tokenEndpoint, code, redirectUri, scope, process.env.VSCODE_CLIENT, process.env.VSCODE_SECRET)
            
            console.log("ID Token Obtained.  Retrieving JAG for XAA using the agent ID...")
            const idJag = await oktaAuth0Exchange.getIdJagFromOkta(tokenEndpoint, tenant, idToken, process.env.AGENT_CLIENT_ID, process.env.AGENT_PRIVATE_KEY_PATH, process.env.AGENT_PRIVATE_KEY_ID)

            console.log("ID JAG Obtained- getting agent access token specific to this managed connection/tenant...")
            const agentAccessToken = await oktaAuth0Exchange.getAccessTokenFromIDJag(tenant, idJag, process.env.AGENT_CLIENT_ID, process.env.AGENT_PRIVATE_KEY_PATH, process.env.AGENT_PRIVATE_KEY_ID)

            console.log("Obtained final agent access token. Attempting to get end user tokens from vault...")
            const vaultedTokenResponse = await vault.exchangeOktaAccessToken(process.env.AUTH0_DOMAIN, agentAccessToken, process.env.AUTH0_CTE_CLIENT_ID, process.env.AUTH0_CTE_CLIENT_SECRET, process.env.AUTH0_VAULT_CLIENT_ID, process.env.AUTH0_VAULT_CLIENT_SECRET, process.env.AUTH0_VAULT_AUDIENCE, process.env.AUTH0_VAULT_SCOPE, tenant.vault_connection)
            console.log(`Response from auth0: ${JSON.stringify(vaultedTokenResponse)}`)

            if (vaultedTokenResponse.success) {
                //I think in this case, we just need to generate an authorization code, and return a response back to hte actual redirect URL. The authorization code would be a cache key for the agent access token.
                outboundRequestCache.clearCachedOutboundRequest(state)
                console.log("Cached credentials already exist. Connected accounts flow is not necessary. Returning details back to the originating redirect_uri.")
                const newAuthzCode = crypto.randomBytes(32).toString('base64url')
                returningAuthzCache.addToCache(newAuthzCode, agentAccessToken, originalState, tenantId, originalParameters)
                const finalRedirectUrl = `${originalParameters.get("redirect_uri")}?code=${newAuthzCode}&state=${originalState}`
                res.redirect (finalRedirectUrl) //Redirect back to the original client with authz and original state.
            }
            else if(vaultedTokenResponse.needsLinking) { //We failed due to lack of credentials
                console.log("Account linking is required. Beginning the account linking flow.")
                console.log(cachedRequest)
                const connectedAccountResponse = await vault.beginConnectedAccountFlow(process.env.AUTH0_DOMAIN, agentAccessToken, process.env.AUTH0_CTE_CLIENT_ID, process.env.AUTH0_CTE_CLIENT_SECRET, state, tenant.vault_connection, `${process.env.PROXY_BASE_URL}/connected_account_callback`, tenant.external_scopes)
                
                if(connectedAccountResponse.success) {
                    //Update our OIDC cache with the access token. When we're done connecting the account we need to stuff it in the authz code cache.
                    outboundRequestCache.cacheOutboundRequest(state, parameters, originalState, originalParameters, agentAccessToken, tenantId)
                    res.redirect(connectedAccountResponse.connectUrl)
                }
                else {
                    return res.status(403).json({
                        error: 'Token Request Failed',
                        message: 'Unable to obtain proper tokens.'
                    })
                }
            }
            else {
                return res.status(403).json({
                    error: 'Token Request Failed',
                    message: 'Unable to obtain proper tokens.'
                })
            }

        } catch (error) {
            console.error('Error exchanging authorization code for tokens:', error.response?.data || error.message)

            // Clear the cached outbound request even on failure to prevent reuse in case something fails very early on.
            outboundRequestCache.clearCachedOutboundRequest(state)

            if (error.response) {
                const errorData = error.response.data
                return res.status(error.response.status).json({
                    error: errorData.error || 'token_exchange_error',
                    error_description: errorData.error_description || 'Failed to exchange authorization code for tokens.',
                    details: errorData
                })
            } else if (error.request) {
                return res.status(502).json({
                    error: 'bad_gateway',
                    error_description: 'No response received from the authorization server during token exchange.'
                })
            } else {
                return res.status(500).json({
                    error: 'server_error',
                    error_description: `Failed to exchange authorization code: ${error.message}`
                })
            }
        }
    })
}