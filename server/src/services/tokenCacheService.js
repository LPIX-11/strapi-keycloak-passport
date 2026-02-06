/**
 * @fileoverview Token caching service for Keycloak access tokens.
 * Implements in-memory caching with automatic refresh before expiry.
 * @module services/tokenCacheService
 * @author Strapi Keycloak Passport Team
 */

import { TOKEN_CACHE } from '../constants.js';

/**
 * @typedef {Object} CachedToken
 * @property {string} accessToken - The Keycloak access token
 * @property {number} expiresAt - Timestamp when token expires
 * @property {number} fetchedAt - Timestamp when token was fetched
 * @property {string} cacheKey - The cache key for this token
 */

/**
 * In-memory token cache storage.
 * Keys are composite identifiers: `${serverUrl}:${realm}:${clientId}`
 * @type {Map<string, CachedToken>}
 */
const tokenCache = new Map();

/**
 * Token cache service factory.
 * Provides in-memory caching for Keycloak admin tokens with automatic expiry handling.
 *
 * @param {Object} params - Service parameters
 * @param {Object} params.strapi - Strapi instance
 * @returns {Object} Token cache service methods
 */
const tokenCacheService = ({ strapi }) => ({
  /**
   * Generates a cache key from Keycloak connection parameters.
   *
   * @param {string} serverUrl - Keycloak server URL
   * @param {string} realm - Keycloak realm name
   * @param {string} clientId - OAuth client ID
   * @returns {string} Composite cache key
   * @private
   */
  _generateCacheKey(serverUrl, realm, clientId) {
    return `${serverUrl}:${realm}:${clientId}`;
  },

  /**
   * Checks if a cached token is still valid (not expired or near expiry).
   *
   * @param {CachedToken} cachedToken - The cached token object
   * @returns {boolean} True if token is still valid and usable
   * @private
   */
  _isTokenValid(cachedToken) {
    if (!cachedToken || !cachedToken.accessToken) {
      return false;
    }

    const now = Date.now();
    const timeUntilExpiry = cachedToken.expiresAt - now;

    // Token is valid if we have more than the buffer time remaining
    return timeUntilExpiry > TOKEN_CACHE.EXPIRY_BUFFER_MS;
  },

  /**
   * Retrieves a cached token if available and valid.
   *
   * @param {string} serverUrl - Keycloak server URL
   * @param {string} realm - Keycloak realm name
   * @param {string} clientId - OAuth client ID
   * @returns {string|null} The cached access token or null if not available/expired
   *
   * @example
   * const token = tokenCacheService.get('https://keycloak.example.com', 'master', 'admin-cli');
   * if (token) {
   *   // Use cached token
   * } else {
   *   // Fetch new token
   * }
   */
  get(serverUrl, realm, clientId) {
    const cacheKey = this._generateCacheKey(serverUrl, realm, clientId);
    const cachedToken = tokenCache.get(cacheKey);

    if (this._isTokenValid(cachedToken)) {
      const timeRemaining = Math.round((cachedToken.expiresAt - Date.now()) / 1000);
      strapi.log.debug(`Token cache hit for ${realm}. Valid for ${timeRemaining}s`);
      return cachedToken.accessToken;
    }

    // Remove expired token from cache
    if (cachedToken) {
      strapi.log.debug(`Token cache miss for ${realm}. Token expired or near expiry.`);
      tokenCache.delete(cacheKey);
    }

    return null;
  },

  /**
   * Stores a token in the cache with expiry information.
   *
   * @param {string} serverUrl - Keycloak server URL
   * @param {string} realm - Keycloak realm name
   * @param {string} clientId - OAuth client ID
   * @param {string} accessToken - The access token to cache
   * @param {number} expiresIn - Token lifetime in seconds (from Keycloak response)
   * @returns {void}
   *
   * @example
   * tokenCacheService.set(
   *   'https://keycloak.example.com',
   *   'master',
   *   'admin-cli',
   *   'eyJhbGciOiJS...',
   *   300 // 5 minutes
   * );
   */
  set(serverUrl, realm, clientId, accessToken, expiresIn) {
    const cacheKey = this._generateCacheKey(serverUrl, realm, clientId);
    const now = Date.now();

    // Calculate expiry timestamp
    const expiresInMs = expiresIn
      ? expiresIn * 1000
      : TOKEN_CACHE.DEFAULT_TOKEN_LIFETIME_MS;

    // Ensure minimum cache time
    const effectiveLifetime = Math.max(expiresInMs, TOKEN_CACHE.MIN_CACHE_TIME_MS);

    /** @type {CachedToken} */
    const cachedToken = {
      accessToken,
      expiresAt: now + effectiveLifetime,
      fetchedAt: now,
      cacheKey,
    };

    tokenCache.set(cacheKey, cachedToken);

    const cacheLifetimeSeconds = Math.round(effectiveLifetime / 1000);
    strapi.log.debug(`Token cached for ${realm}. Expires in ${cacheLifetimeSeconds}s`);
  },

  /**
   * Invalidates a specific cached token.
   * Use when credentials change or on explicit logout.
   *
   * @param {string} serverUrl - Keycloak server URL
   * @param {string} realm - Keycloak realm name
   * @param {string} clientId - OAuth client ID
   * @returns {boolean} True if a token was removed
   *
   * @example
   * // Invalidate when realm config changes
   * tokenCacheService.invalidate('https://keycloak.example.com', 'master', 'admin-cli');
   */
  invalidate(serverUrl, realm, clientId) {
    const cacheKey = this._generateCacheKey(serverUrl, realm, clientId);
    const existed = tokenCache.has(cacheKey);

    if (existed) {
      tokenCache.delete(cacheKey);
      strapi.log.debug(`Token cache invalidated for ${realm}`);
    }

    return existed;
  },

  /**
   * Invalidates all tokens for a specific server URL.
   * Use when the Keycloak server configuration changes.
   *
   * @param {string} serverUrl - Keycloak server URL
   * @returns {number} Number of tokens invalidated
   */
  invalidateByServer(serverUrl) {
    let count = 0;

    for (const [key] of tokenCache) {
      if (key.startsWith(`${serverUrl}:`)) {
        tokenCache.delete(key);
        count++;
      }
    }

    if (count > 0) {
      strapi.log.debug(`Invalidated ${count} cached tokens for server ${serverUrl}`);
    }

    return count;
  },

  /**
   * Clears all cached tokens.
   * Use during plugin shutdown or configuration reset.
   *
   * @returns {number} Number of tokens cleared
   */
  clear() {
    const count = tokenCache.size;
    tokenCache.clear();

    if (count > 0) {
      strapi.log.debug(`Token cache cleared. Removed ${count} tokens.`);
    }

    return count;
  },

  /**
   * Gets cache statistics for monitoring.
   *
   * @returns {Object} Cache statistics
   * @property {number} size - Number of cached tokens
   * @property {Object[]} entries - Array of cache entry info (without tokens)
   */
  getStats() {
    const entries = [];

    for (const [key, value] of tokenCache) {
      const now = Date.now();
      entries.push({
        cacheKey: key,
        fetchedAt: new Date(value.fetchedAt).toISOString(),
        expiresAt: new Date(value.expiresAt).toISOString(),
        isValid: this._isTokenValid(value),
        timeRemainingMs: Math.max(0, value.expiresAt - now),
      });
    }

    return {
      size: tokenCache.size,
      entries,
    };
  },

  /**
   * Checks if a valid token exists in cache without returning it.
   *
   * @param {string} serverUrl - Keycloak server URL
   * @param {string} realm - Keycloak realm name
   * @param {string} clientId - OAuth client ID
   * @returns {boolean} True if a valid token is cached
   */
  has(serverUrl, realm, clientId) {
    const cacheKey = this._generateCacheKey(serverUrl, realm, clientId);
    const cachedToken = tokenCache.get(cacheKey);
    return this._isTokenValid(cachedToken);
  },

  /**
   * Gets the time remaining until a cached token expires.
   *
   * @param {string} serverUrl - Keycloak server URL
   * @param {string} realm - Keycloak realm name
   * @param {string} clientId - OAuth client ID
   * @returns {number} Milliseconds until expiry, or 0 if not cached/expired
   */
  getTimeRemaining(serverUrl, realm, clientId) {
    const cacheKey = this._generateCacheKey(serverUrl, realm, clientId);
    const cachedToken = tokenCache.get(cacheKey);

    if (!cachedToken) {
      return 0;
    }

    return Math.max(0, cachedToken.expiresAt - Date.now());
  },
});

export default tokenCacheService;
