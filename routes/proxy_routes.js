'use strict'

const axios = require('axios')

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
        console.log("Proxy path is:")
        console.log(proxyPath)
        console.log(`[${tenantConfig.id}] Proxying ${req.method} request to: ${targetUrl}`)

        try {
            // Forward the request to the backend
            const backendResponse = await axios({
                method: req.method,
                url: targetUrl,
                headers: {
                    // Forward select headers, excluding host and whatever authorization was sent on the original request inbound.
                    'Content-Type': req.headers['content-type'] || 'application/json',
                    'Accept': req.headers['accept'] || 'application/json'
                },
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
