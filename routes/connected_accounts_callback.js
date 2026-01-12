'use strict'

const crypto = require('crypto')
const axios = require('axios')
const sessionCache = require('../lib/connected_account_session_cache')
const outboundRequestCache = require('../lib/outbound_request_cache')
const returningAuthzCache = require("../lib/return_authz_cache")

/**
 * Connected Account Callback Routes
 * 
 * This module handles the callback from Auth0's Connected Accounts flow.
 * After a user authorizes a connection with an external provider, Auth0
 * redirects them back to this callback endpoint with a connect_code.
 * 
 * @see https://auth0.com/docs/secure/call-apis-on-users-behalf/token-vault/connected-accounts-for-token-vault#complete-connected-accounts-request
 */

/**
 * Connects the callback routes to the Express app.
 */
module.exports.connect = function (app) {

    /**
     * GET /callback
     * 
     * Handles the callback from Auth0's Connected Accounts flow.
     * This endpoint receives the connect_code and state from Auth0 after
     * the user has authorized the connection with the external provider.
     * 
     * Query Parameters:
     * - state: The state value that was sent in the initial connect request
     * - connect_code: The single-use code from Auth0 to complete the flow
     * 
     * The state is used to retrieve the cached auth_session, which is then
     * used along with the connect_code to complete the Connected Accounts request.
     */
    app.get('/connected_account_callback', async (req, res) => {
        const { state, connect_code } = req.query

        // Validate required parameters
        if (!state) {
            return res.status(400).json({
                error: 'Missing Parameter',
                message: 'The state parameter is required.'
            })
        }

        if (!connect_code) {
            return res.status(400).json({
                error: 'Missing Parameter',
                message: 'The connect_code parameter is required.'
            })
        }

        // Retrieve the cached auth_session using the state value
        const cachedData = sessionCache.getCachedAuthSession(state)

        // Clear the cached session data as soon as we get it.
        sessionCache.clearCachedAuthSession(state)

        if (!cachedData) {
            return res.status(400).json({
                error: 'Invalid or Expired State',
                message: 'The state parameter is invalid or has expired. Please restart the connection flow.'
            })
        }

        const { authSession, userToken, oidcState } = cachedData

        // Complete the Connected Accounts request by calling Auth0's complete endpoint
        const completeUrl = `https://${process.env.AUTH0_DOMAIN}/me/v1/connected-accounts/complete`
        const redirectUri = `${process.env.PROXY_BASE_URL}/connected_account_callback`
        
        try {
            const requestBody = {
                auth_session: authSession,
                connect_code: connect_code,
                redirect_uri: redirectUri
            }
            //TODO: This really should be in a library like the rest of my endpoints do when they post to Okta or Auth0.
            console.log('Completing Connected Accounts request:')
            console.log(requestBody)
            console.log(cachedData)
            const response = await axios.post(completeUrl, requestBody, {
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${userToken}`
                }
            })

            console.log('Connected Accounts complete response:')
            console.log(response.data)

            // Now that we're done with the account linking- return back to the original client and give them an authz code they can exchange for tokens.
            //TODO: I haven't added in the ID_TOKEN to the response yet. I need to do this!
            //TODO: Maybe i look at the scopes, and only return the ID token if openid scope was requested?
            console.log("Returning details back to the originating redirect_uri.")

            const oidcCachedData = outboundRequestCache.getCachedOutboundRequest(oidcState)
            outboundRequestCache.clearCachedOutboundRequest(oidcState)
            console.log(oidcCachedData)

            const newAuthzCode = crypto.randomBytes(32).toString('base64url')
            returningAuthzCache.addToCache(newAuthzCode, oidcCachedData.accessToken, oidcCachedData.originalState, oidcCachedData.tenantId, oidcCachedData.originalParameters)
            const finalRedirectUrl = `${oidcCachedData.originalParameters.get("redirect_uri")}?code=${newAuthzCode}&state=${oidcCachedData.originalState}`

            res.redirect (finalRedirectUrl) //Redirect back to the original client with authz and original state.
        } catch (error) {
            console.error('Error completing Connected Accounts request:', error.response?.data || error.message)

            // Clear the cached session data even on failure to prevent reuse
            sessionCache.clearCachedAuthSession(state)

            if (error.response) {
                const errorData = error.response.data
                return res.status(error.response.status).json({
                    error: 'Connected Accounts Error',
                    message: errorData.error_description || errorData.error || 'Failed to complete the connected account flow.',
                    details: errorData
                })
            } else if (error.request) {
                return res.status(502).json({
                    error: 'Bad Gateway',
                    message: 'No response received from Auth0 when completing the connected account flow.'
                })
            } else {
                return res.status(500).json({
                    error: 'Internal Server Error',
                    message: `Failed to complete the connected account flow: ${error.message}`
                })
            }
        }
    })
}
