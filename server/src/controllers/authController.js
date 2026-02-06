/**
 * @fileoverview Authentication controller for role management endpoints.
 * Provides API endpoints for fetching Keycloak roles and managing role mappings.
 * @module controllers/authController
 * @author Strapi Keycloak Passport Team
 */

'use strict';

import {
  PLUGIN_ID,
  PLUGIN_NAMESPACE,
  SERVICES,
} from '../constants.js';
import { extractSafeError } from '../utils/errors.js';

/**
 * @typedef {Object} KoaContext
 * @property {Object} request - Koa request object
 * @property {Object} state - Request state including user info
 * @property {Function} send - Send response function
 * @property {Function} badRequest - Send 400 response function
 */

/**
 * Gets the Keycloak service instance.
 *
 * @returns {Object} Keycloak service
 * @private
 */
const getKeycloakService = () => {
  return strapi.plugin(PLUGIN_ID).service('keycloakService');
};

/**
 * Gets the role mapping service instance.
 *
 * @returns {Object} Role mapping service
 * @private
 */
const getRoleMappingService = () => {
  return strapi.service(SERVICES.ROLE_MAPPING);
};

/**
 * Gets the plugin configuration.
 *
 * @returns {Object} Plugin configuration
 * @private
 */
const getConfig = () => {
  return strapi.config.get(PLUGIN_NAMESPACE);
};

/**
 * Authentication controller.
 * Handles Keycloak role fetching and role mapping management.
 */
export default {
  /**
   * Fetches all Keycloak roles and Strapi admin roles.
   * Filters out excluded roles based on plugin configuration.
   *
   * @async
   * @param {KoaContext} ctx - Koa context
   * @returns {Promise<void>}
   *
   * @example
   * // GET /strapi-keycloak-passport/keycloak-roles
   * // Response: { keycloakRoles: [...], strapiRoles: [...] }
   */
  async getRoles(ctx) {
    try {
      const config = getConfig();
      const keycloakService = getKeycloakService();

      // Fetch Keycloak realm roles
      const allRoles = await keycloakService.fetchRealmRoles();

      // Filter out excluded roles
      const excludedRoles = config.roleConfigs?.excludedRoles || [];
      const keycloakRoles = allRoles.filter(
        (role) => !excludedRoles.includes(role.name)
      );

      // Fetch Strapi admin roles
      const strapiRoles = await strapi.entityService.findMany('admin::role', {
        sort: { name: 'asc' },
      });

      strapi.log.debug(`Fetched ${keycloakRoles.length} Keycloak roles and ${strapiRoles.length} Strapi roles`);

      return ctx.send({
        keycloakRoles,
        strapiRoles,
      });
    } catch (error) {
      strapi.log.error('Failed to fetch roles:', error.message);

      const safeError = extractSafeError(error);
      return ctx.badRequest(safeError.message, { error: safeError });
    }
  },

  /**
   * Retrieves Keycloak-to-Strapi role mappings.
   * Returns mappings as an object for easy lookup.
   *
   * @async
   * @param {KoaContext} ctx - Koa context
   * @returns {Promise<void>}
   *
   * @example
   * // GET /strapi-keycloak-passport/get-keycloak-role-mappings
   * // Response: { "ADMIN": 1, "EDITOR": 2 }
   */
  async getRoleMappings(ctx) {
    try {
      const roleMappingService = getRoleMappingService();
      const mappings = await roleMappingService.getMappingsAsObject();

      strapi.log.debug(`Retrieved ${Object.keys(mappings).length} role mappings`);

      return ctx.send(mappings);
    } catch (error) {
      strapi.log.error('Failed to retrieve role mappings:', error.message);

      const safeError = extractSafeError(error);
      return ctx.badRequest(safeError.message, { error: safeError });
    }
  },

  /**
   * Saves Keycloak-to-Strapi role mappings.
   * Replaces all existing mappings with the provided ones.
   *
   * @async
   * @param {KoaContext} ctx - Koa context
   * @returns {Promise<void>}
   *
   * @example
   * // POST /strapi-keycloak-passport/save-keycloak-role-mappings
   * // Body: { mappings: { "ADMIN": 1, "EDITOR": 2 } }
   * // Response: { message: "Mappings saved successfully." }
   */
  async saveRoleMappings(ctx) {
    try {
      const { mappings } = ctx.request.body || {};

      // Validate request body
      if (!mappings || typeof mappings !== 'object') {
        return ctx.badRequest('Invalid request body. Expected { mappings: {...} }');
      }

      // Get performing user for audit logging
      const performedBy = ctx.state?.user
        ? { id: ctx.state.user.id, email: ctx.state.user.email }
        : null;

      const roleMappingService = getRoleMappingService();
      await roleMappingService.saveMappings(mappings, performedBy);

      strapi.log.info(`Saved ${Object.keys(mappings).length} role mappings`);

      return ctx.send({
        message: 'Mappings saved successfully.',
        count: Object.keys(mappings).length,
      });
    } catch (error) {
      strapi.log.error('Failed to save role mappings:', error.message);

      const safeError = extractSafeError(error);
      return ctx.badRequest(safeError.message, { error: safeError });
    }
  },

  /**
   * Tests the Keycloak connection.
   * Attempts to fetch an admin token to verify connectivity.
   *
   * @async
   * @param {KoaContext} ctx - Koa context
   * @returns {Promise<void>}
   *
   * @example
   * // GET /strapi-keycloak-passport/test-connection
   * // Response: { success: true, message: "Connected", serverUrl: "...", realm: "..." }
   */
  async testConnection(ctx) {
    try {
      const keycloakService = getKeycloakService();
      const result = await keycloakService.testConnection();

      return ctx.send(result);
    } catch (error) {
      strapi.log.error('Connection test failed:', error.message);

      return ctx.send({
        success: false,
        message: error.safeMessage || error.message,
      });
    }
  },

  /**
   * Gets token cache statistics for monitoring.
   *
   * @async
   * @param {KoaContext} ctx - Koa context
   * @returns {Promise<void>}
   *
   * @example
   * // GET /strapi-keycloak-passport/token-cache-stats
   * // Response: { size: 1, entries: [...] }
   */
  async getTokenCacheStats(ctx) {
    try {
      const keycloakService = getKeycloakService();
      const stats = keycloakService.getTokenCacheStats();

      return ctx.send(stats);
    } catch (error) {
      strapi.log.error('Failed to get token cache stats:', error.message);

      const safeError = extractSafeError(error);
      return ctx.badRequest(safeError.message, { error: safeError });
    }
  },

  /**
   * Invalidates the cached Keycloak admin token.
   * Use when credentials have changed or for testing.
   *
   * @async
   * @param {KoaContext} ctx - Koa context
   * @returns {Promise<void>}
   *
   * @example
   * // POST /strapi-keycloak-passport/invalidate-token
   * // Response: { success: true, message: "Token invalidated" }
   */
  async invalidateToken(ctx) {
    try {
      const keycloakService = getKeycloakService();
      const invalidated = keycloakService.invalidateToken();

      return ctx.send({
        success: true,
        message: invalidated ? 'Token invalidated' : 'No token to invalidate',
        tokenWasPresent: invalidated,
      });
    } catch (error) {
      strapi.log.error('Failed to invalidate token:', error.message);

      const safeError = extractSafeError(error);
      return ctx.badRequest(safeError.message, { error: safeError });
    }
  },
};
