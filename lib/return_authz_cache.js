'use strict'
/**
 * In-memory client request cache for caching the returning authz code along with original state and access token.
 * 
 * This module provides a simple in-memory cache for storing this stuff.
 */

// In-memory cache for storing auth requests.
// Key: state value, Value: object containing all querystring parameters.
const returningAuthorizationCache = new Map()

// Cache TTL in milliseconds (15 minutes - typical OAuth flow timeout)
const CACHE_TTL_MS = 15 * 60 * 1000

/**
 * Stores an OAuth2 /authorize request in the cache using state as the key
 * @param {string} parameters - The querystring from the /authorize request
 * @returns {Object} - The parsed and cached request object
 * @throws {Error} - If the querystring does not contain a state parameter
 */
function addToCache(returnAuthzCode, accessToken, originalState, tenantId, originalParameters) {
  const cacheEntry = {
    originalState: originalState,
    tenantId: tenantId,
    originalParameters: originalParameters,
    accessToken: accessToken,
    createdAt: Date.now()
  }
  
  returningAuthorizationCache.set(returnAuthzCode, cacheEntry)
  return cacheEntry
}

/**
 * Retrieves a cached OAuth2 authorize request by state value
 * @param {string} state - The state value used as the cache key
 * @returns {Object|null} - The cached request object or null if not found/expired
 */
function getCacheItem(returnAuthzCode) {
  const cached = returningAuthorizationCache.get(returnAuthzCode)
  if (!cached) {
    return null
  }
  
  // Check if the cache entry has expired
  if (Date.now() - cached.createdAt > CACHE_TTL_MS) {
    returningAuthorizationCache.delete(returnAuthzCode)
    return null
  }
  
  return cached
}

/**
 * Clears a cached client request entry
 * @param {string} state - The state value used as the cache key
 */
function clearCacheItem(returnAuthzCode) {
  returningAuthorizationCache.delete(returnAuthzCode)
}

module.exports = {
  addToCache,
  getCacheItem,
  clearCacheItem
}
