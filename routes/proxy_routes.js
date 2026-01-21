'use strict'

const axios = require('axios')
const vault = require('../lib/token_vault')

/**
 * Connects proxy routes to the Express app.
 * All requests to /:tenantId/proxy/* are forwarded to the tenant's backend URL.
 */
module.exports.connect = function (app, tenantMiddleware, authMiddleware) {

    // Catch-all proxy route
    app.all('/:tenantId/*', tenantMiddleware, authMiddleware, async (req, res) => {
        const tenantConfig = req.tenantConfig
        const proxyPath = req.params[0] // Everything after /, defaulting to empty string.
        const targetUrl = `${tenantConfig.backend_url}/${proxyPath}`
        console.log(req.params)
        console.log("Proxy path is:")
        console.log(proxyPath)
        console.log(`[${tenantConfig.id}] Proxying ${req.method} request to: ${targetUrl}`)

        //First, if there is a valid vault connection set up on the tenantConfig, let's attempt to get the external token from Vault.
        let vaultedToken = ''

        if(tenantConfig.vault_connection) {
            console.log("Vault was configured for this tenant- getting a new token using inbound token:")
            console.log(req.authContext.accessToken)
            const vaultedTokenResponse = await vault.exchangeOktaAccessToken(process.env.AUTH0_DOMAIN, req.authContext.accessToken, process.env.AUTH0_CTE_CLIENT_ID, process.env.AUTH0_CTE_CLIENT_SECRET, process.env.AUTH0_VAULT_CLIENT_ID, process.env.AUTH0_VAULT_CLIENT_SECRET, process.env.AUTH0_VAULT_AUDIENCE, process.env.AUTH0_VAULT_SCOPE, tenantConfig.vault_connection)
            console.log(vaultedTokenResponse)
            if(vaultedTokenResponse.success) {
                vaultedToken = vaultedTokenResponse.accessToken
            }
            else if(vaultedTokenResponse.needsLinking) { //We failed due to lack of credentials
                console.log("Account linking is required. Return a 401, with instructions on what to do.")

                return res.status(401).json({
                        error: 'Account Linking Required',
                        message: 'A connected account linking is required to obtain tokens for the backend service. Please re-log in.',
                    })
            }
            else { //We straight up failed.
                return res.status(403).json({
                    error: 'Token Request Failed',
                    message: 'Unable to obtain proper tokens.'
                })
            }
        }

        try {
            // Forward the request to the backend. Including a vaulted token if vaulting was configured for the given tenant.
            let backendHeaders = {
                    // Forward select headers, excluding host and whatever authorization was sent on the original request inbound.
                    'Content-Type': req.headers['content-type'] || 'application/json',
                    'Accept': req.headers['accept'] || 'application/json'
            
            }
            if(vaultedToken) {
                backendHeaders['Authorization'] = `Bearer ${vaultedToken}`
            }

            const backendResponse = await axios({
                method: req.method,
                url: targetUrl,
                headers: backendHeaders,
                data: ['POST', 'PUT', 'PATCH'].includes(req.method) ? req.body : undefined,
                params: req.query,
                timeout: 30000,
                validateStatus: () => true // Don't throw on non-2xx status
            })

            // Forward response headers
            const headersToForward = ['content-type', 'cache-control', 'etag', 'last-modified']
            headersToForward.forEach(header => {
                if (backendResponse.headers[header]) {
                    res.setHeader(header, backendResponse.headers[header])
                }
            })

            // Send response
            res.status(backendResponse.status).send(backendResponse.data)

        } catch (error) {
            console.error(`[${tenantConfig.id}] Proxy error:`, error.message)

            if (error.code === 'ECONNREFUSED') {
                return res.status(502).json({
                    error: 'Bad Gateway',
                    message: 'Unable to connect to backend service.'
                })
            }

            if (error.code === 'ETIMEDOUT' || error.code === 'ECONNABORTED') {
                return res.status(504).json({
                    error: 'Gateway Timeout',
                    message: 'Backend service request timed out.'
                })
            }

            res.status(500).json({
                error: 'Internal Server Error',
                message: 'An error occurred while processing the request.'
            })
        }
    })
}
