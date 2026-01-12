'use strict'

const crypto = require('crypto')
const tenantConfig = require('../lib/tenant_config')
const outboundRequestCache = require('../lib/outbound_request_cache')

/**
 * OAuth 2.0 Authorize Endpoint Proxy
 * 
 * This module provides a proxy authorize endpoint that redirects to the
 * real authorization server's /authorize endpoint. It acts as a pass-through,
 * forwarding all query parameters to the upstream authorization server.
 */
module.exports.connect = function (app) {

    /**
     * GET /authorize/:tenantId
     * 
     * Redirects to the real OAuth 2.0 authorization endpoint for the specified tenant.
     * All query parameters (client_id, redirect_uri, scope, state, etc.) are forwarded
     * to the upstream authorization server.
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
            // Cache the inbound OAuth2 request - state parameter from req.query is used as key.
            const inboundAuthParameters = new URLSearchParams(req.query)
            const inboundState = inboundAuthParameters.get('state')

            // Build a new authorize request using the proxy client
            const authorizeEndpoint = `${process.env.OKTA_DOMAIN}/oauth2/v1/authorize`
            console.log(`Final Authorize endpoint ${authorizeEndpoint}`)
            
            // Generate a new random state for the outbound request
            const outboundState = crypto.randomBytes(32).toString('base64url')
            const outboundNonce = crypto.randomBytes(32).toString('base64url')
            
            // Build new query parameters for the proxy authorize request
            let proxyQueryParams = new URLSearchParams()
            proxyQueryParams.set("client_id", process.env.VSCODE_CLIENT)
            proxyQueryParams.set("redirect_uri", `${process.env.PROXY_BASE_URL}/callback`)
            proxyQueryParams.set("response_type", "code")
            proxyQueryParams.set("scope", "openid")
            proxyQueryParams.set("state", outboundState)
            proxyQueryParams.set("nonce", outboundNonce)
            //proxyQueryParams.set("code_challenge", inboundAuthParameters.get("code_challenge"))
            //proxyQueryParams.set("code_challenge_method", inboundAuthParameters.get("code_challenge_method"))

            // Cache the outbound authorize request using the outbound state as the key
            //TODO: Need to add a nonce to the outbound cache so I can validate it on the callback.
            outboundRequestCache.cacheOutboundRequest(outboundState, proxyQueryParams, inboundState, inboundAuthParameters, null, tenantId)

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
