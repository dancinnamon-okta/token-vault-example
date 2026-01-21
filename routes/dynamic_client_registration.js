'use strict'

const tenantConfig = require('../lib/tenant_config')

/**
 * RFC 7591 - OAuth 2.0 Dynamic Client Registration Protocol
 * Implements the /register endpoint
 * 
 * This endpoint returns hard-coded client registration metadata
 * based on the tenant configuration.
 * 
 * Once complete, this endpoint will inspect the inbound /register call by the client, and it will perform a look-up on known, approved clients. It will then return those details.
 * It is expected to use the inbound redirect_uri to determine which pre-registered information to pass back.
 */
//TODO: Need to handle multiple public clients- not just VSCODE.
module.exports.connect = function (app) {

    // RFC 7591 Dynamic Client Registration endpoint
    app.post('/register', async (req, res) => {
        try {
            // Build the client registration response per RFC 7591
            const clientMetadata = {
                // Client identifier issued by the authorization server
                client_id: process.env.VSCODE_CLIENT,
                 
                // Time at which the client identifier was issued
                client_id_issued_at: Math.floor(Date.now() / 1000),
                
                // Time at which the client secret expires (0 = never)
                client_secret_expires_at: 0,
                
                // Array of redirect URIs
                //TODO: This is VSCODE specific. Need to handle other public clients.
                //TODO: Parse inbound request, and determine what public client we have.
                redirect_uris: [
                    "http://127.0.0.1:33418",
                    "https://vscode.dev/redirect"
                ],

                // Token endpoint authentication method
                token_endpoint_auth_method: 'none',
                
                // Grant types the client is allowed to use
                grant_types: ['authorization_code', 'refresh_token'],
                
                // Response types the client is allowed to use
                response_types: ['code'],
                
                // Human-readable client name
                client_name: `VSCode Proxy Client`,
                
                // Scopes the client is allowed to request
                // I've found this to be derived from the authorization_server_metadata.
                scope: []
            }

            res.status(201).json(clientMetadata)
            
        } catch (error) {
            console.error('Error in dynamic client registration:', error)
            res.status(500).json({
                error: 'server_error',
                error_description: 'An internal server error occurred.'
            })
        }
    })
}
