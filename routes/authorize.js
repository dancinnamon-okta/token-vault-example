'use strict'

const crypto = require('crypto')
const tenantConfig = require('../lib/tenant_config')
const oidcRequestCache = require('../lib/oidc_cache')

/**
 * OAuth 2.0 Authorize Endpoint Proxy
 * 
 * This module provides a proxy authorize endpoint that redirects to the
 * real authorization server's /authorize endpoint.
 * 
 * When this endpoint is invoked, it caches off the original inbound request, and begins a brand new /authorize request with the IDP.
 * During this request's callback, (as defined in oidc_callback.js), we have the ability to ensure the user's credentials are vaulted.
 * If account linking is required, we're still in the browser, so we'll begin (and complete) that flow while the user's browser is still active.
 * Flow if account linking is required: authorize.js -> oidc_callback.js -> vault for account linking -> connected_accounts_callback.js -> client.
 * Flow is account linking is NOT required: authorize.js -> oidc_callback.js -> client.
 */
module.exports.connect = function (app) {

    /**
     * GET /authorize/:tenantId
     * 
     * Caches off the inbound reqeust and Redirects to the real OAuth 2.0 authorization endpoint for the specified tenant. 
     * 
     * @param {string} tenantId - The tenant identifier from the URL path
     * @returns {302} Redirect to the real authorization endpoint
     */
    app.get('/authorize/:tenantId', async (req, res) => {
        const tenantId = req.params.tenantId
        
        try {
            const tenant = tenantConfig.getTenantConfig(tenantId)
            
            if (!tenant) {
                return res.status(404).json({
                    error: 'Not Found',
                    message: `Tenant '${tenantId}' not found.`
                })
            }
            console.log("Found a valid tenant...")
            // Cache the inbound OAuth2 request - OIDC state parameter is used as key.
            const inboundAuthParameters = new URLSearchParams(req.query)
            const inboundState = inboundAuthParameters.get('state')
            const inboundClientId = inboundAuthParameters.get('client_id')

            // Build a new authorize request using the proxy client
            const authorizeEndpoint = `${process.env.OKTA_DOMAIN}/oauth2/v1/authorize`
            console.log(`Final Authorize endpoint ${authorizeEndpoint}`)
            
            // Generate a new random state for the outbound request
            const outboundState = crypto.randomBytes(32).toString('base64url')
            const outboundNonce = crypto.randomBytes(32).toString('base64url')
            
            // Build new query parameters for the proxy authorize request
            let proxyQueryParams = new URLSearchParams()
            proxyQueryParams.set("client_id", inboundClientId)
            proxyQueryParams.set("redirect_uri", `${process.env.PROXY_BASE_URL}/callback`)
            proxyQueryParams.set("response_type", "code")
            proxyQueryParams.set("scope", "openid profile")
            proxyQueryParams.set("state", outboundState)
            proxyQueryParams.set("nonce", outboundNonce)

            // Cache the outbound authorize request using the outbound state as the key
            oidcRequestCache.cacheOidcRequest(outboundState, proxyQueryParams, inboundState, inboundAuthParameters, null, null, null, tenantId)

            const redirectUrl = `${authorizeEndpoint}?${proxyQueryParams.toString()}`

            console.log(`Redirecting to authorization endpoint: ${redirectUrl}`)
            
            // Return 302 redirect to the real authorize endpoint
            return res.redirect(302, redirectUrl)

        } catch (error) {
            console.error(`Error processing authorize request for tenant ${tenantId}:`, error.message)
            return res.status(500).json({
                error: 'Internal Server Error',
                message: 'Unable to process authorization request.'
            })
        }
    })
}
