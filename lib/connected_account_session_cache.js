'use strict'

/**
 * In-memory session cache for Connected Accounts flow
 * 
 * This module provides a simple in-memory cache for storing auth_session and state
 * values during the Connected Accounts OAuth flow. The state value is used as the
 * lookup key for subsequent callback requests.
 */

// In-memory cache for storing auth_session and state values during Connected Accounts flow
// Key: state value, Value: { authSession, state, createdAt }
const connectedAccountsCache = new Map()

// Cache TTL in milliseconds (15 minutes - typical OAuth flow timeout)
const CACHE_TTL_MS = 15 * 60 * 1000

/**
 * Stores auth session data in the cache using state as the key
 * @param {string} state - The state value used as the cache key
 * @param {string} authSession - The auth_session value from Auth0
 * @param {string} userToken - The user's Auth0 token for subsequent API calls
 */
function cacheAuthSession(state, oidcState, authSession, userToken) {
  connectedAccountsCache.set(state, {
    authSession: authSession,
    state: state,
    oidcState: oidcState,
    userToken: userToken,
    createdAt: Date.now()
  })
}

/**
 * Retrieves cached auth session data by state value
 * @param {string} state - The state value used as the cache key
 * @returns {Object|null} - The cached data or null if not found/expired
 */
function getCachedAuthSession(state) {
  const cached = connectedAccountsCache.get(state)
  if (!cached) {
    return null
  }
  
  // Check if the cache entry has expired
  if (Date.now() - cached.createdAt > CACHE_TTL_MS) {
    connectedAccountsCache.delete(state)
    return null
  }
  
  return cached
}

/**
 * Clears a cached auth session entry
 * @param {string} state - The state value used as the cache key
 */
function clearCachedAuthSession(state) {
  connectedAccountsCache.delete(state)
}

module.exports = {
  cacheAuthSession,
  getCachedAuthSession,
  clearCachedAuthSession
}
