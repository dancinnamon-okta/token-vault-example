'use strict'

/**
 * In-memory outbound request cache for caching the proxy's outbound /authorize requests.
 * 
 * This module provides a simple in-memory cache for storing outbound authorize requests
 * that are sent to the upstream authorization server.
 */

// In-memory cache for storing outbound auth requests.
// Key: outbound state value, Value: object containing all outbound request parameters.
const outboundRequestsCache = new Map()

// Cache TTL in milliseconds (15 minutes - typical OAuth flow timeout)
const CACHE_TTL_MS = 15 * 60 * 1000

/**
 * Stores an outbound OAuth2 /authorize request in the cache using the outbound state as the key
 * @param {string} outboundState - The generated outbound state value
 * @param {string} tenantId - The tenant identifier
 * @param {URLSearchParams} parameters - The outbound request parameters
 * @returns {Object} - The cached request object
 */
function cacheOutboundRequest(outboundState, parameters, originalState, originalParameters, accessToken, tenantId) {
  const cacheEntry = {
    tenantId: tenantId,
    parameters: parameters,
    originalState: originalState,
    originalParameters: originalParameters,
    accessToken: accessToken,
    createdAt: Date.now()
  }
  
  outboundRequestsCache.set(outboundState, cacheEntry)
  return cacheEntry
}

/**
 * Retrieves a cached outbound OAuth2 authorize request by state value
 * @param {string} state - The outbound state value used as the cache key
 * @returns {Object|null} - The cached request object or null if not found/expired
 */
function getCachedOutboundRequest(state) {
  const cached = outboundRequestsCache.get(state)
  if (!cached) {
    return null
  }
  
  // Check if the cache entry has expired
  if (Date.now() - cached.createdAt > CACHE_TTL_MS) {
    outboundRequestsCache.delete(state)
    return null
  }
  
  return cached
}

/**
 * Clears a cached outbound request entry
 * @param {string} state - The outbound state value used as the cache key
 */
function clearCachedOutboundRequest(state) {
  outboundRequestsCache.delete(state)
}

module.exports = {
  cacheOutboundRequest,
  getCachedOutboundRequest,
  clearCachedOutboundRequest
}
