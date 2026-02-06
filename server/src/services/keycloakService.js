/**
 * @fileoverview Keycloak API service for authentication and role management.
 * Supports both Keycloak 17+ (modern) and legacy URL formats.
 * Implements token caching, error sanitization, and comprehensive logging.
 * @module services/keycloakService
 * @author Strapi Keycloak Passport Team
 */

import axios from 'axios';
import {
  PLUGIN_NAMESPACE,
  KEYCLOAK_PATHS,
  KEYCLOAK_ENDPOINTS,
  HTTP,
  ERROR_CODES,
} from '../constants.js';
import { createSanitizedError, createKeycloakError } from '../utils/errors.js';

/**
 * @typedef {Object} KeycloakConfig
 * @property {string} KEYCLOAK_AUTH_URL - Base URL of the Keycloak server
 * @property {string} KEYCLOAK_REALM - Keycloak realm name
 * @property {string} KEYCLOAK_CLIENT_ID - OAuth client ID
 * @property {string} KEYCLOAK_CLIENT_SECRET - OAuth client secret
 * @property {boolean} [KEYCLOAK_LEGACY_MODE] - Use legacy /auth prefix for pre-17 servers
 */

/**
 * @typedef {Object} TokenResponse
 * @property {string} access_token - The OAuth access token
 * @property {number} expires_in - Token lifetime in seconds
 * @property {string} token_type - Token type (usually "Bearer")
 * @property {string} [refresh_token] - Optional refresh token
 * @property {string} [scope] - Granted scopes
 */

/**
 * @typedef {Object} KeycloakRole
 * @property {string} id - Role ID
 * @property {string} name - Role name
 * @property {string} [description] - Role description
 * @property {boolean} [composite] - Whether this is a composite role
 */

/**
 * Keycloak service factory.
 * Provides methods for interacting with Keycloak Admin API and OAuth endpoints.
 *
 * @param {Object} params - Service parameters
 * @param {Object} params.strapi - Strapi instance
 * @returns {Object} Keycloak service methods
 */
const keycloakService = ({ strapi }) => ({
  /**
   * Gets the plugin configuration.
   *
   * @returns {KeycloakConfig} Plugin configuration
   * @private
   */
  _getConfig() {
    return strapi.config.get(PLUGIN_NAMESPACE);
  },

  /**
   * Gets the token cache service instance.
   *
   * @returns {Object} Token cache service
   * @private
   */
  _getTokenCache() {
    return strapi.plugin('strapi-keycloak-passport').service('tokenCacheService');
  },

  /**
   * Determines the auth path prefix based on Keycloak version configuration.
   * Keycloak 17+ uses no prefix, while legacy versions use /auth.
   *
   * @returns {string} The auth path prefix
   * @private
   */
  _getAuthPrefix() {
    const config = this._getConfig();
    return config.KEYCLOAK_LEGACY_MODE
      ? KEYCLOAK_PATHS.LEGACY_AUTH_PREFIX
      : KEYCLOAK_PATHS.MODERN_AUTH_PREFIX;
  },

  /**
   * Builds a Keycloak endpoint URL with proper path handling.
   *
   * @param {string} endpointTemplate - Endpoint template from KEYCLOAK_ENDPOINTS
   * @param {Object} [params] - Parameters to substitute in the template
   * @returns {string} Complete endpoint URL
   * @private
   *
   * @example
   * const url = this._buildEndpointUrl(KEYCLOAK_ENDPOINTS.TOKEN);
   * // Returns: https://keycloak.example.com/realms/master/protocol/openid-connect/token
   */
  _buildEndpointUrl(endpointTemplate, params = {}) {
    const config = this._getConfig();
    const authPrefix = this._getAuthPrefix();

    // Start with base URL (remove trailing slash if present)
    let url = config.KEYCLOAK_AUTH_URL.replace(/\/+$/, '');

    // Add auth prefix if in legacy mode
    url += authPrefix;

    // Replace template parameters
    let endpoint = endpointTemplate
      .replace('{realm}', config.KEYCLOAK_REALM)
      .replace('{userId}', params.userId || '');

    url += endpoint;

    return url;
  },

  /**
   * Fetches an admin access token from Keycloak using client credentials.
   * Implements caching to reduce API calls and improve performance.
   *
   * @async
   * @returns {Promise<string>} The Keycloak access token
   * @throws {PluginError} If authentication fails
   *
   * @example
   * const token = await keycloakService.fetchAdminToken();
   * // Use token for admin API calls
   */
  async fetchAdminToken() {
    const config = this._getConfig();
    const tokenCache = this._getTokenCache();

    // Check cache first
    const cachedToken = tokenCache.get(
      config.KEYCLOAK_AUTH_URL,
      config.KEYCLOAK_REALM,
      config.KEYCLOAK_CLIENT_ID
    );

    if (cachedToken) {
      return cachedToken;
    }

    // Fetch new token
    const tokenUrl = this._buildEndpointUrl(KEYCLOAK_ENDPOINTS.TOKEN);

    try {
      const response = await axios.post(
        tokenUrl,
        new URLSearchParams({
          client_id: config.KEYCLOAK_CLIENT_ID,
          client_secret: config.KEYCLOAK_CLIENT_SECRET,
          grant_type: HTTP.GRANT_TYPES.CLIENT_CREDENTIALS,
        }).toString(),
        {
          headers: {
            [HTTP.HEADERS.CONTENT_TYPE]: HTTP.CONTENT_TYPES.FORM_URLENCODED,
          },
        }
      );

      /** @type {TokenResponse} */
      const tokenData = response.data;

      if (!tokenData?.access_token) {
        throw createSanitizedError(
          ERROR_CODES.KEYCLOAK_TOKEN_ERROR,
          'Keycloak returned response without access_token',
          'Failed to authenticate with Keycloak.'
        );
      }

      // Cache the token
      tokenCache.set(
        config.KEYCLOAK_AUTH_URL,
        config.KEYCLOAK_REALM,
        config.KEYCLOAK_CLIENT_ID,
        tokenData.access_token,
        tokenData.expires_in
      );

      strapi.log.info('Successfully fetched and cached Keycloak admin token.');
      return tokenData.access_token;
    } catch (error) {
      // Don't wrap PluginErrors
      if (error.code && error.safeMessage) {
        throw error;
      }

      strapi.log.error('Keycloak admin token fetch failed:', {
        status: error.response?.status,
        data: error.response?.data,
        message: error.message,
      });

      throw createKeycloakError('token fetch', error);
    }
  },

  /**
   * Fetches all realm roles from Keycloak.
   *
   * @async
   * @returns {Promise<KeycloakRole[]>} Array of Keycloak roles
   * @throws {PluginError} If role fetch fails
   *
   * @example
   * const roles = await keycloakService.fetchRealmRoles();
   * // [{ id: '...', name: 'admin' }, { id: '...', name: 'user' }]
   */
  async fetchRealmRoles() {
    const accessToken = await this.fetchAdminToken();
    const rolesUrl = this._buildEndpointUrl(KEYCLOAK_ENDPOINTS.REALM_ROLES);

    try {
      const response = await axios.get(rolesUrl, {
        headers: {
          [HTTP.HEADERS.AUTHORIZATION]: `Bearer ${accessToken}`,
          [HTTP.HEADERS.ACCEPT]: HTTP.CONTENT_TYPES.JSON,
        },
      });

      /** @type {KeycloakRole[]} */
      const roles = response.data || [];

      strapi.log.debug(`Fetched ${roles.length} realm roles from Keycloak`);
      return roles;
    } catch (error) {
      strapi.log.error('Failed to fetch Keycloak realm roles:', {
        status: error.response?.status,
        data: error.response?.data,
        message: error.message,
      });

      throw createSanitizedError(
        ERROR_CODES.KEYCLOAK_ROLES_ERROR,
        `Failed to fetch realm roles: ${error.response?.status || error.message}`,
        'Failed to fetch roles from Keycloak. Ensure the client has realm-management roles.',
        { status: error.response?.status }
      );
    }
  },

  /**
   * Fetches the realm roles assigned to a specific user.
   *
   * @async
   * @param {string} keycloakUserId - The Keycloak user ID (sub claim)
   * @returns {Promise<string[]>} Array of role names assigned to the user
   * @throws {PluginError} If user ID is invalid or fetch fails
   *
   * @example
   * const roles = await keycloakService.fetchUserRoles('abc-123-def');
   * // ['admin', 'user']
   */
  async fetchUserRoles(keycloakUserId) {
    if (!keycloakUserId || typeof keycloakUserId !== 'string') {
      throw createSanitizedError(
        ERROR_CODES.INVALID_PAYLOAD,
        `Invalid Keycloak user ID: ${keycloakUserId}`,
        'Invalid user identifier provided.'
      );
    }

    const accessToken = await this.fetchAdminToken();
    const rolesUrl = this._buildEndpointUrl(
      KEYCLOAK_ENDPOINTS.USER_REALM_ROLES,
      { userId: keycloakUserId }
    );

    try {
      const response = await axios.get(rolesUrl, {
        headers: {
          [HTTP.HEADERS.AUTHORIZATION]: `Bearer ${accessToken}`,
          [HTTP.HEADERS.ACCEPT]: HTTP.CONTENT_TYPES.JSON,
        },
      });

      /** @type {KeycloakRole[]} */
      const roles = response.data || [];

      // Extract role names
      const roleNames = roles.map((role) => role.name);

      strapi.log.debug(`Fetched ${roleNames.length} roles for user ${keycloakUserId}`);
      return roleNames;
    } catch (error) {
      strapi.log.error(`Failed to fetch roles for user ${keycloakUserId}:`, {
        status: error.response?.status,
        data: error.response?.data,
        message: error.message,
      });

      throw createSanitizedError(
        ERROR_CODES.KEYCLOAK_ROLES_ERROR,
        `Failed to fetch user roles for ${keycloakUserId}: ${error.response?.status || error.message}`,
        'Failed to fetch user roles from Keycloak.'
      );
    }
  },

  /**
   * Tests the connection to Keycloak by attempting to fetch an admin token.
   *
   * @async
   * @returns {Promise<Object>} Connection test result
   * @property {boolean} success - Whether the connection succeeded
   * @property {string} [message] - Success or error message
   * @property {string} [serverVersion] - Detected Keycloak URL format
   *
   * @example
   * const result = await keycloakService.testConnection();
   * if (result.success) {
   *   console.log('Connected:', result.message);
   * }
   */
  async testConnection() {
    const config = this._getConfig();

    try {
      await this.fetchAdminToken();

      return {
        success: true,
        message: 'Successfully connected to Keycloak',
        serverUrl: config.KEYCLOAK_AUTH_URL,
        realm: config.KEYCLOAK_REALM,
        urlFormat: config.KEYCLOAK_LEGACY_MODE ? 'legacy (/auth)' : 'modern (17+)',
      };
    } catch (error) {
      return {
        success: false,
        message: error.safeMessage || error.message,
        serverUrl: config.KEYCLOAK_AUTH_URL,
        realm: config.KEYCLOAK_REALM,
        urlFormat: config.KEYCLOAK_LEGACY_MODE ? 'legacy (/auth)' : 'modern (17+)',
      };
    }
  },

  /**
   * Invalidates the cached admin token.
   * Call this when configuration changes or on explicit logout.
   *
   * @returns {boolean} True if a token was invalidated
   */
  invalidateToken() {
    const config = this._getConfig();
    const tokenCache = this._getTokenCache();

    return tokenCache.invalidate(
      config.KEYCLOAK_AUTH_URL,
      config.KEYCLOAK_REALM,
      config.KEYCLOAK_CLIENT_ID
    );
  },

  /**
   * Gets the current token cache status for monitoring.
   *
   * @returns {Object} Token cache statistics
   */
  getTokenCacheStats() {
    const tokenCache = this._getTokenCache();
    return tokenCache.getStats();
  },
});

export default keycloakService;
