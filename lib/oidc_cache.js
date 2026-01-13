'use strict'

/**
 * In-memory outbound request cache for caching the proxy's outbound /authorize requests.
 * 
 * This module provides a simple in-memory cache for storing outbound authorize requests
 * that are sent to the upstream authorization server.
 */

// In-memory cache for storing outbound auth requests.
// Key: outbound state value, Value: object containing all outbound request parameters.
const oidcCache = new Map()

// Cache TTL in milliseconds (15 minutes - typical OAuth flow timeout)
const CACHE_TTL_MS = 15 * 60 * 1000

/**
 * Stores an outbound OAuth2 /authorize request in the cache using the outbound state as the key
 * @param {string} outboundState - The generated outbound state value
 * @param {string} tenantId - The tenant identifier
 * @param {URLSearchParams} parameters - The outbound request parameters
 * @returns {Object} - The cached request object
 */
function cacheOidcRequest(outboundState, parameters, originalState, originalParameters, accessToken, accessTokenScope, accessTokenExpiresIn, tenantId) {
  const cacheEntry = {
    tenantId: tenantId,
    parameters: parameters,
    originalState: originalState,
    originalParameters: originalParameters,
    accessToken: accessToken,
    accessTokenScope: accessTokenScope,
    accessTokenExpiresIn: accessTokenExpiresIn,
    createdAt: Date.now()
  }
  
  oidcCache.set(outboundState, cacheEntry)
  return cacheEntry
}

/**
 * Retrieves a cached outbound OAuth2 authorize request by state value
 * @param {string} state - The outbound state value used as the cache key
 * @returns {Object|null} - The cached request object or null if not found/expired
 */
function getOidcRequest(state) {
  const cached = oidcCache.get(state)
  if (!cached) {
    return null
  }
  
  // Check if the cache entry has expired
  if (Date.now() - cached.createdAt > CACHE_TTL_MS) {
    oidcCache.delete(state)
    return null
  }
  
  return cached
}

/**
 * Clears a cached outbound request entry
 * @param {string} state - The outbound state value used as the cache key
 */
function clearOidcRequest(state) {
  oidcCache.delete(state)
}

module.exports = {
  cacheOidcRequest,
  getOidcRequest,
  clearOidcRequest
}
