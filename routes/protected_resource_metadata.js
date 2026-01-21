'use strict'

const tenantConfig = require('../lib/tenant_config')

/**
 * RFC 9728 - OAuth 2.0 Protected Resource Metadata
 * Implements the /.well-known/oauth-protected-resource endpoint
 * 
 * This endpoint advertises metadata about the protected resource,
 * including which authorization servers can be used to obtain access tokens.
 */
module.exports.connect = function (app) {

    // RFC 9728 Protected Resource Metadata endpoint
    app.get('/.well-known/oauth-protected-resource/:tenantId/*', async (req, res) => {
        const tenantId = req.params.tenantId
        const proxyPath = req.params[0]

        try {
            const tenant = tenantConfig.getTenantConfig(tenantId)
            
            if (!tenant) {
                return res.status(404).json({
                    error: 'Not Found',
                    message: `Tenant '${tenantId}' not found.`
                })
            }

            // Build the protected resource metadata response per RFC 9728
            const metadata = {
                // REQUIRED: The protected resource's resource identifier
                resource: `${process.env.PROXY_BASE_URL}/${tenantId}/${proxyPath}`,
                
                // Passing back ourselves as authz server as well because we're hosting our own metadata.
                authorization_servers: [`${process.env.PROXY_BASE_URL}/${tenantId}/${proxyPath}`],
                
                // OPTIONAL: Human-readable name for the resource
                resource_name: `Okta AI Relay Protected Resource - ${tenantId}`,
            }

            return res.status(200).json(metadata)

        } catch (error) {
            console.error(`Error fetching protected resource metadata for tenant ${tenantId}:`, error.message)
            return res.status(500).json({
                error: 'Internal Server Error',
                message: 'Unable to retrieve protected resource metadata.'
            })
        }
    })
}
