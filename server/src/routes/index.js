/**
 * @fileoverview Route definitions for the Strapi Keycloak Passport plugin.
 * Defines all API endpoints with their handlers, authentication, and middleware.
 * @module routes
 * @author Strapi Keycloak Passport Team
 */

import checkAdminPermission from '../middlewares/checkAdminPermission.js';
import { PERMISSIONS } from '../constants.js';

/**
 * Plugin route definitions.
 * All routes are prefixed with `/strapi-keycloak-passport/` by Strapi.
 *
 * @type {Array<Object>}
 */
const routes = [
  /**
   * Admin Login Override
   * Replaces Strapi's default /admin/login with Keycloak authentication.
   */
  {
    method: 'POST',
    path: '/admin/login',
    handler: 'authOverrideController.login',
    config: {
      auth: false,
      description: 'Authenticate admin user via Keycloak OAuth2',
    },
  },

  /**
   * Get Keycloak and Strapi Roles
   * Fetches available roles for mapping configuration.
   */
  {
    method: 'GET',
    path: '/keycloak-roles',
    handler: 'authController.getRoles',
    config: {
      auth: false,
      policies: [],
      middlewares: [checkAdminPermission(PERMISSIONS.ACCESS)],
      description: 'Fetch available Keycloak and Strapi admin roles',
    },
  },

  /**
   * Get Role Mappings
   * Retrieves saved Keycloak-to-Strapi role mappings.
   */
  {
    method: 'GET',
    path: '/get-keycloak-role-mappings',
    handler: 'authController.getRoleMappings',
    config: {
      auth: false,
      policies: [],
      middlewares: [checkAdminPermission(PERMISSIONS.VIEW_MAPPINGS)],
      description: 'Get saved Keycloak to Strapi role mappings',
    },
  },

  /**
   * Save Role Mappings
   * Persists Keycloak-to-Strapi role mappings.
   */
  {
    method: 'POST',
    path: '/save-keycloak-role-mappings',
    handler: 'authController.saveRoleMappings',
    config: {
      auth: false,
      policies: [],
      middlewares: [checkAdminPermission(PERMISSIONS.MANAGE_MAPPINGS)],
      description: 'Save Keycloak to Strapi role mappings',
    },
  },

  /**
   * Test Keycloak Connection
   * Verifies connectivity to Keycloak server.
   */
  {
    method: 'GET',
    path: '/test-connection',
    handler: 'authController.testConnection',
    config: {
      auth: false,
      policies: [],
      middlewares: [checkAdminPermission(PERMISSIONS.ACCESS)],
      description: 'Test connection to Keycloak server',
    },
  },

  /**
   * Get Token Cache Statistics
   * Returns information about cached admin tokens.
   */
  {
    method: 'GET',
    path: '/token-cache-stats',
    handler: 'authController.getTokenCacheStats',
    config: {
      auth: false,
      policies: [],
      middlewares: [checkAdminPermission(PERMISSIONS.ACCESS)],
      description: 'Get token cache statistics for monitoring',
    },
  },

  /**
   * Invalidate Cached Token
   * Forces refresh of the cached admin token.
   */
  {
    method: 'POST',
    path: '/invalidate-token',
    handler: 'authController.invalidateToken',
    config: {
      auth: false,
      policies: [],
      middlewares: [checkAdminPermission(PERMISSIONS.MANAGE_MAPPINGS)],
      description: 'Invalidate the cached Keycloak admin token',
    },
  },
];

export default routes;
