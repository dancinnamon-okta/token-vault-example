'use strict'

const tenantConfig = require('../lib/tenant_config')

/**
 * RFC 8414 - OAuth 2.0 Authorization Server Metadata
 * Implements the /.well-known/oauth-authorization-server endpoint
 * 
 * This endpoint advertises metadata about the authorization server,
 * including endpoints, supported features, and capabilities.
 */
module.exports.connect = function (app) {

    // RFC 8414 Authorization Server Metadata endpoint
    app.get('/.well-known/oauth-authorization-server/:tenantId/*', async (req, res) => {
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

            // Build the authorization server metadata response per RFC 8414
            const metadata = {
                // REQUIRED: The authorization server's issuer identifier
                issuer: tenant.issuer,
                
                // REQUIRED: URL of the authorization endpoint
                //This will actually point to our internal proxy.
                authorization_endpoint: `${process.env.PROXY_BASE_URL}/authorize/${tenantId}`,
                
                // REQUIRED: URL of the token endpoint
                token_endpoint: `${process.env.PROXY_BASE_URL}/token`,
                
                // OPTIONAL: URL of the JWK Set document
                jwks_uri: tenant.keys_endpoint,
                
                // We're going to give them a local register endpoint that will return hard-coded data.
                registration_endpoint: `${process.env.PROXY_BASE_URL}/register`,
                
                // RECOMMENDED: JSON array of scopes supported
                scopes_supported: tenant.external_scopes,
                
                // REQUIRED: JSON array of response types supported
                response_types_supported: ['code'],
                
                // OPTIONAL: JSON array of response modes supported
                response_modes_supported: ['query'],
                
                // OPTIONAL: JSON array of grant types supported
                grant_types_supported: ['authorization_code'],
                
                // OPTIONAL: JSON array of client authentication methods supported
                token_endpoint_auth_methods_supported: ['none', 'client_secret_basic', 'client_secret_post'],
                
                // OPTIONAL: JSON array of PKCE code challenge methods supported
                code_challenge_methods_supported: ['S256'],
                
                // OPTIONAL: URL of the protected resource metadata endpoint (RFC 9728)
                protected_resources: [`${process.env.PROXY_BASE_URL}/.well-known/oauth-protected-resource/${tenantId}/${proxyPath}`]
            }
            
            return res.status(200).json(metadata)

        } catch (error) {
            console.error(`Error fetching authorization server metadata for tenant ${tenantId}:`, error.message)
            return res.status(500).json({
                error: 'Internal Server Error',
                message: 'Unable to retrieve authorization server metadata.'
            })
        }
    })
}
