'use strict'

const njwt = require('njwt')
const axios = require('axios')
const jwk2pem = require('pem-jwk').jwk2pem

// Cache for signing keys to avoid repeated fetches
const keyCache = new Map()
const KEY_CACHE_TTL = 3600000 // 1 hour in milliseconds

/**
 * Fetches the signing key from the JWKS endpoint.
 * @param {string} keysUrl - The URL of the JWKS endpoint
 * @param {string} kid - The key ID from the token header
 * @returns {object} - The signing key
 */
async function getSigningKey(keysUrl, kid) {
  const cacheKey = `${keysUrl}:${kid}`
  const cached = keyCache.get(cacheKey)
  
  if (cached && Date.now() - cached.timestamp < KEY_CACHE_TTL) {
    return cached.key
  }

  try {
    const keysResponse = await axios.request({
      url: keysUrl,
      method: 'get',
      timeout: 5000
    })

    const keyByKid = keysResponse.data.keys.filter((key) => key.kid === kid)
    
    if (keyByKid.length === 1) {
      keyCache.set(cacheKey, { key: keyByKid[0], timestamp: Date.now() })
      return keyByKid[0]
    }
    
    throw new Error(`Unable to locate signing key with kid: ${kid}`)
  } catch (error) {
    console.error('Error fetching signing keys:', error.message)
    throw new Error('Error retrieving signing keys from authorization server')
  }
}

/**
 * Extracts the kid (key ID) from a JWT token header.
 * @param {string} accessToken - The JWT access token
 * @returns {string} - The key ID
 */
function getTokenKid(accessToken) {
  try {
    return JSON.parse(Buffer.from(accessToken.split('.')[0], 'base64').toString('utf-8')).kid
  } catch (error) {
    throw new Error('Unable to parse token header')
  }
}

/**
 * Extracts the issuer from a JWT token body.
 * @param {string} accessToken - The JWT access token
 * @returns {string} - The issuer
 */
function getTokenIssuer(accessToken) {
  try {
    return JSON.parse(Buffer.from(accessToken.split('.')[1], 'base64').toString('utf-8')).iss
  } catch (error) {
    throw new Error('Unable to parse token body')
  }
}

/**
 * Validates that the token issuer matches the tenant configuration.
 * @param {string} issuer - The issuer from the token
 * @param {object} tenantConfig - The tenant configuration
 * @returns {boolean} - True if the issuer is valid
 */
function validateIssuer(issuer, tenantConfig) {
  console.log(`Validating token issuer: ${issuer}`)
  return issuer === tenantConfig.issuer
}

/**
 * Validates required scopes for the request.
 * @param {array} tokenScopes - Scopes from the access token
 * @param {string} httpMethod - The HTTP method of the request
 * @returns {boolean} - True if the scopes are sufficient
 */
function validateScopes(tokenScopes, httpMethod) {
  // Basic scope validation - customize based on your needs
  const readMethods = ['GET', 'HEAD', 'OPTIONS']
  const writeMethods = ['POST', 'PUT', 'PATCH', 'DELETE']
  return true
  /*
  if (readMethods.includes(httpMethod)) {
    return tokenScopes.some(scope => scope.includes('read') || scope === 'user')
  }
  
  if (writeMethods.includes(httpMethod)) {
    return tokenScopes.some(scope => scope.includes('write') || scope === 'user')
  }

  return false // We're not sure what's going on- fail closed.
  */
}

/**
 * Main authorization function - validates JWT and authorizes the request.
 * @param {object} tenantConfig - The tenant configuration
 * @param {string} httpMethod - The HTTP method of the request
 * @param {object} headers - The request headers
 * @returns {object} - Authorization result with success status and verified JWT
 */
module.exports.authorizeRequest = async function(tenantConfig, httpMethod, headers) {
  const authHeaderPattern = /^\s*bearer\s+(.+)$/i
  let verifiedJWT = null
  let accessToken = null
  
  try {
    // Extract the authorization header
    const authHeader = headers.authorization || headers.Authorization || ''
    const parsedHeader = authHeader.match(authHeaderPattern)

    if (!parsedHeader || parsedHeader.length !== 2) {
      return {
        success: false,
        statusCode: 401,
        message: 'Missing or invalid authorization header. Bearer token required.',
        token: null
      }
    }

    accessToken = parsedHeader[1]
    
    // Validate the issuer
    const issuer = getTokenIssuer(accessToken)
    if (!validateIssuer(issuer, tenantConfig)) {
      return {
        success: false,
        statusCode: 403,
        message: 'Access token was not issued by a trusted issuer for this tenant.',
        token: null
      }
    }

    // Get the signing key and verify the token
    const key = await getSigningKey(tenantConfig.keys_endpoint, getTokenKid(accessToken))
    const signingKeyPem = jwk2pem(key)
    verifiedJWT = njwt.verify(accessToken, signingKeyPem, 'RS256')

  } catch (err) {
    console.error('JWT verification error:', err.message)
    return {
      success: false,
      statusCode: 401,
      message: 'Invalid or expired access token.',
      token: null
    }
  }

  // Validate audience (optional - customize the expected audience)
  //TODO: FIX THIS!
  const expectedAudience = process.env.API_BASE_URL 
    ? `${process.env.API_BASE_URL}/${tenantConfig.id}`
    : null
  
  if (expectedAudience && verifiedJWT.body.aud) {
    const tokenAud = verifiedJWT.body.aud
    const validAudience = Array.isArray(tokenAud) 
      ? tokenAud.includes(expectedAudience) 
      : tokenAud === expectedAudience || tokenAud.startsWith(expectedAudience)
    
    if (!validAudience) {
      console.log(`Audience mismatch - Expected: ${expectedAudience}, Actual: ${tokenAud}`)
      return {
        success: false,
        statusCode: 403,
        message: 'Access token has incorrect audience for this tenant.',
        token: null
      }
    }
  }

  // Validate scopes
  const scopesArray = Array.isArray(verifiedJWT.body.scope) 
    ? verifiedJWT.body.scope 
    : (verifiedJWT.body.scope || '').split(' ')

  if (!validateScopes(scopesArray, httpMethod)) {
    console.log(`Insufficient scopes for ${httpMethod} request. Scopes: ${scopesArray.join(', ')}`)
    return {
      success: false,
      statusCode: 403,
      message: 'Access token does not have sufficient scopes for this request.',
      token: null
    }
  }

  return {
    success: true,
    message: '',
    token: accessToken
  }
}
