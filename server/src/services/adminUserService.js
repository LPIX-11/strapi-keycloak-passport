/**
 * @fileoverview Admin user management service for Keycloak-authenticated users.
 * Handles user synchronization, role mapping, and lifecycle management.
 * @module services/adminUserService
 * @author Strapi Keycloak Passport Team
 */

import {
  PLUGIN_ID,
  PLUGIN_NAMESPACE,
  SERVICES,
  AUDIT_ACTIONS,
  ERROR_CODES,
} from '../constants.js';
import { createSanitizedError } from '../utils/errors.js';

/**
 * @typedef {Object} KeycloakUserInfo
 * @property {string} email - User's email address
 * @property {string} sub - Keycloak user ID
 * @property {string} [preferred_username] - Preferred username
 * @property {string} [given_name] - First name
 * @property {string} [family_name] - Last name
 * @property {boolean} [email_verified] - Whether email is verified
 */

/**
 * @typedef {Object} StrapiAdminUser
 * @property {number|string} id - User ID
 * @property {string} documentId - Strapi v5 document ID
 * @property {string} email - User email
 * @property {string} [firstname] - First name
 * @property {string} [lastname] - Last name
 * @property {string} [username] - Username
 * @property {boolean} isActive - Whether user is active
 * @property {Object[]} roles - Assigned admin roles
 */

/**
 * @typedef {Object} RoleMapping
 * @property {string} keycloakRole - Keycloak role name
 * @property {number} strapiRole - Strapi role ID
 */

/**
 * Admin user service factory.
 * Provides user lifecycle management with Keycloak integration.
 *
 * @param {Object} params - Service parameters
 * @param {Object} params.strapi - Strapi instance
 * @returns {Object} Admin user service methods
 */
const adminUserService = ({ strapi }) => ({
  /**
   * Gets the Keycloak service instance.
   *
   * @returns {Object} Keycloak service
   * @private
   */
  _getKeycloakService() {
    return strapi.plugin(PLUGIN_ID).service('keycloakService');
  },

  /**
   * Gets the role mapping service instance.
   *
   * @returns {Object} Role mapping service
   * @private
   */
  _getRoleMappingService() {
    return strapi.service(SERVICES.ROLE_MAPPING);
  },

  /**
   * Gets the audit log service instance.
   *
   * @returns {Object} Audit log service
   * @private
   */
  _getAuditLogService() {
    return strapi.plugin(PLUGIN_ID).service('auditLogService');
  },

  /**
   * Gets the plugin configuration.
   *
   * @returns {Object} Plugin configuration
   * @private
   */
  _getConfig() {
    return strapi.config.get(PLUGIN_NAMESPACE);
  },

  /**
   * Extracts normalized user data from Keycloak userinfo response.
   *
   * @param {KeycloakUserInfo} userInfo - Keycloak user info
   * @returns {Object} Normalized user data
   * @private
   */
  _normalizeUserData(userInfo) {
    return {
      email: userInfo.email?.toLowerCase()?.trim(),
      username: userInfo.preferred_username || '',
      firstname: userInfo.given_name || '',
      lastname: userInfo.family_name || '',
      keycloakUserId: userInfo.sub,
    };
  },

  /**
   * Finds an existing admin user by email.
   *
   * @param {string} email - User's email address
   * @returns {Promise<StrapiAdminUser|null>} Found user or null
   * @private
   */
  async _findUserByEmail(email) {
    const [user] = await strapi.entityService.findMany('admin::user', {
      filters: { email },
      populate: { roles: true },
      limit: 1,
    });

    return user || null;
  },

  /**
   * Maps Keycloak roles to Strapi role IDs using stored mappings.
   *
   * @param {string[]} keycloakRoles - Array of Keycloak role names
   * @returns {Promise<number[]>} Array of Strapi role IDs
   * @private
   */
  async _mapRolesToStrapi(keycloakRoles) {
    const roleMappingService = this._getRoleMappingService();
    const config = this._getConfig();

    /** @type {RoleMapping[]} */
    const mappings = await roleMappingService.getMappings();

    /** @type {Set<number>} */
    const strapiRoleIds = new Set();

    // Map each Keycloak role to Strapi role
    for (const keycloakRole of keycloakRoles) {
      const mapping = mappings.find((m) => m.keycloakRole === keycloakRole);
      if (mapping) {
        strapiRoleIds.add(mapping.strapiRole);
      }
    }

    // Fall back to default role if no mappings found
    if (strapiRoleIds.size === 0) {
      strapiRoleIds.add(config.roleConfigs.defaultRoleId);
    }

    return Array.from(strapiRoleIds);
  },

  /**
   * Determines if user roles need to be updated.
   *
   * @param {number[]} currentRoleIds - Current Strapi role IDs
   * @param {number[]} newRoleIds - New role IDs from mapping
   * @returns {boolean} True if roles need updating
   * @private
   */
  _rolesNeedUpdate(currentRoleIds, newRoleIds) {
    if (currentRoleIds.length !== newRoleIds.length) {
      return true;
    }

    const currentSet = new Set(currentRoleIds);
    return newRoleIds.some((id) => !currentSet.has(id));
  },

  /**
   * Creates a new admin user with the given data.
   *
   * @param {Object} userData - User data to create
   * @param {number[]} roleIds - Role IDs to assign
   * @param {Object} [ctx] - Koa context for audit logging
   * @returns {Promise<StrapiAdminUser>} Created user
   * @private
   */
  async _createUser(userData, roleIds, ctx = null) {
    const auditLogService = this._getAuditLogService();

    const newUser = await strapi.entityService.create('admin::user', {
      data: {
        email: userData.email,
        firstname: userData.firstname,
        lastname: userData.lastname,
        username: userData.username,
        isActive: true,
        roles: roleIds,
      },
    });

    strapi.log.info(`Created new admin user: ${userData.email}`);

    // Log audit entry (non-blocking)
    auditLogService.logUserCreated({
      email: userData.email,
      userId: String(newUser.id),
      keycloakUserId: userData.keycloakUserId,
      roles: roleIds,
    }, ctx);

    return newUser;
  },

  /**
   * Updates an existing admin user.
   *
   * @param {StrapiAdminUser} existingUser - User to update
   * @param {Object} userData - New user data
   * @param {number[]} roleIds - New role IDs
   * @param {Object} [ctx] - Koa context for audit logging
   * @returns {Promise<StrapiAdminUser>} Updated user
   * @private
   */
  async _updateUser(existingUser, userData, roleIds, ctx = null) {
    const auditLogService = this._getAuditLogService();

    // Extract current role IDs for comparison
    const currentRoleIds = (existingUser.roles || []).map((r) => r.id);

    // Determine what's changing
    const changes = {};
    if (userData.firstname !== existingUser.firstname) {
      changes.firstname = { from: existingUser.firstname, to: userData.firstname };
    }
    if (userData.lastname !== existingUser.lastname) {
      changes.lastname = { from: existingUser.lastname, to: userData.lastname };
    }
    if (this._rolesNeedUpdate(currentRoleIds, roleIds)) {
      changes.roles = { from: currentRoleIds, to: roleIds };
    }

    // Skip update if nothing changed
    if (Object.keys(changes).length === 0) {
      strapi.log.debug(`No changes detected for user: ${userData.email}`);
      return existingUser;
    }

    const updatedUser = await strapi.documents('admin::user').update({
      documentId: existingUser.documentId,
      data: {
        firstname: userData.firstname,
        lastname: userData.lastname,
        roles: roleIds,
      },
    });

    strapi.log.info(`Updated admin user: ${userData.email}`, { changes });

    // Log audit entry (non-blocking)
    auditLogService.logUserUpdated({
      email: userData.email,
      userId: String(existingUser.id),
      changes,
    }, ctx);

    return updatedUser;
  },

  /**
   * Finds or creates an admin user in Strapi and assigns the correct role.
   * This is the main entry point for user synchronization during login.
   *
   * @async
   * @param {KeycloakUserInfo} userInfo - User data from Keycloak
   * @param {Object} [ctx] - Koa context for audit logging and client info
   * @returns {Promise<StrapiAdminUser>} The created or updated Strapi admin user
   * @throws {PluginError} If user sync fails
   *
   * @example
   * const adminUser = await adminUserService.findOrCreate({
   *   email: 'user@example.com',
   *   sub: 'keycloak-user-id',
   *   given_name: 'John',
   *   family_name: 'Doe'
   * }, ctx);
   */
  async findOrCreate(userInfo, ctx = null) {
    // Validate input
    if (!userInfo?.email) {
      throw createSanitizedError(
        ERROR_CODES.INVALID_PAYLOAD,
        'User info missing required email field',
        'Invalid user data received from authentication provider.'
      );
    }

    if (!userInfo?.sub) {
      throw createSanitizedError(
        ERROR_CODES.INVALID_PAYLOAD,
        'User info missing required sub (Keycloak user ID) field',
        'Invalid user data received from authentication provider.'
      );
    }

    try {
      // Normalize user data
      const userData = this._normalizeUserData(userInfo);

      // Find existing user
      const existingUser = await this._findUserByEmail(userData.email);

      // Fetch Keycloak roles and map to Strapi roles
      let keycloakRoles = [];
      try {
        const keycloakService = this._getKeycloakService();
        keycloakRoles = await keycloakService.fetchUserRoles(userData.keycloakUserId);
      } catch (error) {
        strapi.log.warn(`Failed to fetch Keycloak roles for ${userData.email}:`, error.message);
        // Continue with default role
      }

      const strapiRoleIds = await this._mapRolesToStrapi(keycloakRoles);

      // Create or update user
      if (!existingUser) {
        return await this._createUser(userData, strapiRoleIds, ctx);
      }

      return await this._updateUser(existingUser, userData, strapiRoleIds, ctx);
    } catch (error) {
      // Re-throw plugin errors
      if (error.code && error.safeMessage) {
        throw error;
      }

      strapi.log.error(`Failed to sync user ${userInfo.email}:`, error.message);

      throw createSanitizedError(
        ERROR_CODES.USER_SYNC_ERROR,
        `User synchronization failed: ${error.message}`,
        'Failed to synchronize user account.'
      );
    }
  },

  /**
   * Finds an admin user by their email address.
   *
   * @async
   * @param {string} email - User's email address
   * @returns {Promise<StrapiAdminUser|null>} Found user or null
   *
   * @example
   * const user = await adminUserService.findByEmail('user@example.com');
   */
  async findByEmail(email) {
    if (!email || typeof email !== 'string') {
      return null;
    }

    return this._findUserByEmail(email.toLowerCase().trim());
  },

  /**
   * Deactivates an admin user account.
   *
   * @async
   * @param {string} email - User's email address
   * @param {Object} [performedBy] - Admin performing the action
   * @returns {Promise<boolean>} True if user was deactivated
   */
  async deactivateUser(email, performedBy = null) {
    const user = await this._findUserByEmail(email);

    if (!user) {
      strapi.log.warn(`Cannot deactivate non-existent user: ${email}`);
      return false;
    }

    await strapi.documents('admin::user').update({
      documentId: user.documentId,
      data: { isActive: false },
    });

    strapi.log.info(`Deactivated admin user: ${email}`);

    // Log audit entry
    const auditLogService = this._getAuditLogService();
    auditLogService.logUserUpdated({
      email,
      userId: String(user.id),
      changes: { isActive: { from: true, to: false } },
    });

    return true;
  },

  /**
   * Gets the default role ID from configuration.
   *
   * @returns {number} Default role ID
   */
  getDefaultRoleId() {
    const config = this._getConfig();
    return config.roleConfigs.defaultRoleId;
  },

  /**
   * Checks if a user exists by email.
   *
   * @async
   * @param {string} email - User's email address
   * @returns {Promise<boolean>} True if user exists
   */
  async userExists(email) {
    const user = await this._findUserByEmail(email);
    return user !== null;
  },
});

export default adminUserService;
