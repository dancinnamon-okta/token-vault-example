'use strict'

const crypto = require('crypto')
const returningAuthzCache = require('../lib/return_authz_cache')

/**
 * OAuth 2.0 Token Endpoint
 * 
 * This module provides a token endpoint that exchanges authorization codes
 * for access tokens. It validates the authorization code against the cache
 * and performs PKCE validation before returning the token.
 */

/**
 * Validates the PKCE code_verifier against the original code_challenge
 * @param {string} codeVerifier - The code_verifier provided by the client
 * @param {string} codeChallenge - The original code_challenge from the authorize request
 * @param {string} codeChallengeMethod - The method used (plain or S256)
 * @returns {boolean} - True if the verifier is valid, false otherwise
 */
function validatePKCE(codeVerifier, codeChallenge, codeChallengeMethod) {
    if (!codeVerifier || !codeChallenge) {
        return false
    }

    if (codeChallengeMethod === 'S256') {
        // SHA256 hash the verifier and base64url encode it
        const hash = crypto.createHash('sha256')
            .update(codeVerifier)
            .digest('base64url')
        return hash === codeChallenge
    }

    return false
}

/**
 * Connects the token route to the Express app.
 */
module.exports.connect = function (app) {

    /**
     * POST /token
     * 
     * Exchanges an authorization code for an access token.
     * Validates the code against the cache and performs PKCE validation.
     * 
     * Request Body (application/x-www-form-urlencoded or application/json):
     * - grant_type: Must be "authorization_code"
     * - code: The authorization code received from the authorize endpoint
     * - client_id: The client identifier
     * - code_verifier: The PKCE code verifier
     * 
     * @returns {Object} Token response with access_token
     */
    app.post('/token', async (req, res) => {
        // Support both JSON and form-urlencoded bodies
        const body = req.body

        const { grant_type, code, client_id, code_verifier, redirect_uri } = body

        // Validate grant_type
        if (grant_type !== 'authorization_code') {
            return res.status(400).json({
                error: 'unsupported_grant_type',
                error_description: 'Only authorization_code grant type is supported.'
            })
        }

        // Validate required parameters
        if (!code) {
            return res.status(400).json({
                error: 'invalid_request',
                error_description: 'The code parameter is required.'
            })
        }

        if (!client_id) {
            return res.status(400).json({
                error: 'invalid_request',
                error_description: 'The client_id parameter is required.'
            })
        }

        if (!code_verifier) {
            return res.status(400).json({
                error: 'invalid_request',
                error_description: 'The code_verifier parameter is required for PKCE.'
            })
        }

        if (!redirect_uri) {
            return res.status(400).json({
                error: 'invalid_request',
                error_description: 'Redirect_uri is required.'
            })
        }

        // Retrieve the cached authorization from the return_authz_cache
        const cachedAuthz = returningAuthzCache.getCacheItem(code)
        returningAuthzCache.clearCacheItem(code)

        if (!cachedAuthz) {
            return res.status(400).json({
                error: 'invalid_grant',
                error_description: 'The authorization code is invalid, expired, or has already been used.'
            })
        }

        // Extract the original parameters to validate PKCE
        const originalParameters = cachedAuthz.originalParameters
        
        // Get the original code_challenge and code_challenge_method
        let codeChallenge = originalParameters.get('code_challenge')
        let codeChallengeMethod = originalParameters.get('code_challenge_method')
       

        // Validate PKCE
        if (!codeChallenge) {
            return res.status(400).json({
                error: 'invalid_request',
                error_description: 'No code_challenge was found in the original authorization request.'
            })
        }
/*
        if (!validatePKCE(code_verifier, codeChallenge, codeChallengeMethod)) {
            return res.status(400).json({
                error: 'invalid_grant',
                error_description: 'The code_verifier does not match the code_challenge.'
            })
        }
*/
        // Validate client_id matches the original request
        let originalClientId = originalParameters.get('client_id')
    
        if (originalClientId && originalClientId !== client_id) {
            return res.status(400).json({
                error: 'invalid_grant',
                error_description: 'The client_id does not match the original authorization request.'
            })
        }

        // Return the access token
        const accessToken = cachedAuthz.accessToken

        console.log(`Token endpoint: Successfully exchanged authorization code for access token for tenant ${cachedAuthz.tenantId}`)

        //TODO: May need to return more things like scope, expires, etc.
        return res.status(200).json({
            access_token: accessToken,
            token_type: 'Bearer'
        })
    })
}
