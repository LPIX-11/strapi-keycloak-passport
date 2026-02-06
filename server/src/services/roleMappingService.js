/**
 * @fileoverview Role mapping service for managing Keycloak to Strapi role mappings.
 * Provides CRUD operations for role mappings with audit logging.
 * @module services/roleMappingService
 * @author Strapi Keycloak Passport Team
 */

import {
  PLUGIN_ID,
  CONTENT_TYPES,
  AUDIT_ACTIONS,
  ERROR_CODES,
} from '../constants.js';
import { createSanitizedError } from '../utils/errors.js';

/**
 * @typedef {Object} RoleMapping
 * @property {number} id - Mapping ID
 * @property {string} documentId - Strapi v5 document ID
 * @property {string} keycloakRole - Keycloak role name
 * @property {number} strapiRole - Strapi role ID
 * @property {Date} createdAt - Creation timestamp
 * @property {Date} updatedAt - Last update timestamp
 */

/**
 * @typedef {Object} RoleMappingInput
 * @property {string} keycloakRole - Keycloak role name
 * @property {number} strapiRole - Strapi role ID
 */

/**
 * Role mapping service factory.
 * Provides CRUD operations for managing Keycloak to Strapi role mappings.
 *
 * @param {Object} params - Service parameters
 * @param {Object} params.strapi - Strapi instance
 * @returns {Object} Role mapping service methods
 */
const roleMappingService = ({ strapi }) => ({
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
   * Validates a role mapping entry.
   *
   * @param {string} keycloakRole - Keycloak role name
   * @param {number} strapiRole - Strapi role ID
   * @throws {PluginError} If validation fails
   * @private
   */
  _validateMapping(keycloakRole, strapiRole) {
    if (!keycloakRole || typeof keycloakRole !== 'string') {
      throw createSanitizedError(
        ERROR_CODES.INVALID_PAYLOAD,
        `Invalid Keycloak role: ${keycloakRole}`,
        'Invalid Keycloak role provided.'
      );
    }

    if (keycloakRole.trim().length === 0) {
      throw createSanitizedError(
        ERROR_CODES.INVALID_PAYLOAD,
        'Keycloak role cannot be empty',
        'Keycloak role name is required.'
      );
    }

    if (!strapiRole || typeof strapiRole !== 'number' || strapiRole < 1) {
      throw createSanitizedError(
        ERROR_CODES.INVALID_PAYLOAD,
        `Invalid Strapi role ID: ${strapiRole}`,
        'Invalid Strapi role ID provided.'
      );
    }
  },

  /**
   * Saves multiple role mappings, replacing all existing mappings.
   * This is an atomic operation - all mappings are replaced at once.
   *
   * @async
   * @param {Object<string, number>} mappings - Object mapping Keycloak roles to Strapi role IDs
   * @param {Object} [performedBy] - Admin user performing the action
   * @param {number} [performedBy.id] - Admin user ID
   * @param {string} [performedBy.email] - Admin user email
   * @returns {Promise<RoleMapping[]>} Array of created mappings
   * @throws {PluginError} If save operation fails
   *
   * @example
   * await roleMappingService.saveMappings({
   *   'ADMIN': 1,
   *   'EDITOR': 2,
   *   'VIEWER': 3
   * }, { id: 1, email: 'admin@example.com' });
   */
  async saveMappings(mappings, performedBy = null) {
    const auditLogService = this._getAuditLogService();

    // Validate all mappings before making any changes
    const entries = Object.entries(mappings);

    for (const [keycloakRole, strapiRole] of entries) {
      this._validateMapping(keycloakRole, strapiRole);
    }

    try {
      // Delete all existing mappings atomically
      await strapi.db.query(CONTENT_TYPES.ROLE_MAPPING).deleteMany({
        where: {
          id: { $notNull: true },
        },
      });

      // Create new mappings
      const createdMappings = [];

      for (const [keycloakRole, strapiRole] of entries) {
        const mapping = await strapi.entityService.create(CONTENT_TYPES.ROLE_MAPPING, {
          data: {
            keycloakRole: keycloakRole.trim(),
            strapiRole,
          },
        });

        createdMappings.push(mapping);

        // Log audit entry for each mapping (non-blocking)
        auditLogService.logMappingChange({
          action: AUDIT_ACTIONS.MAPPING_CREATED,
          keycloakRole: keycloakRole.trim(),
          strapiRole,
          performedBy,
        });
      }

      strapi.log.info(`Saved ${createdMappings.length} role mappings`);
      return createdMappings;
    } catch (error) {
      // Re-throw plugin errors
      if (error.code && error.safeMessage) {
        throw error;
      }

      strapi.log.error('Failed to save role mappings:', error.message);

      throw createSanitizedError(
        ERROR_CODES.ROLE_MAPPING_ERROR,
        `Failed to save role mappings: ${error.message}`,
        'Failed to save role mappings.'
      );
    }
  },

  /**
   * Retrieves all role mappings from the database.
   *
   * @async
   * @returns {Promise<RoleMapping[]>} Array of role mappings
   * @throws {PluginError} If retrieval fails
   *
   * @example
   * const mappings = await roleMappingService.getMappings();
   * // [{ keycloakRole: 'ADMIN', strapiRole: 1 }, ...]
   */
  async getMappings() {
    try {
      const mappings = await strapi.entityService.findMany(CONTENT_TYPES.ROLE_MAPPING, {
        sort: { keycloakRole: 'asc' },
      });

      return mappings || [];
    } catch (error) {
      strapi.log.error('Failed to retrieve role mappings:', error.message);

      throw createSanitizedError(
        ERROR_CODES.ROLE_MAPPING_ERROR,
        `Failed to retrieve role mappings: ${error.message}`,
        'Failed to retrieve role mappings.'
      );
    }
  },

  /**
   * Retrieves mappings as an object (Keycloak role -> Strapi role ID).
   *
   * @async
   * @returns {Promise<Object<string, number>>} Mapping object
   *
   * @example
   * const mappings = await roleMappingService.getMappingsAsObject();
   * // { 'ADMIN': 1, 'EDITOR': 2 }
   */
  async getMappingsAsObject() {
    const mappings = await this.getMappings();

    return mappings.reduce((acc, mapping) => {
      acc[mapping.keycloakRole] = mapping.strapiRole;
      return acc;
    }, {});
  },

  /**
   * Gets a specific mapping by Keycloak role name.
   *
   * @async
   * @param {string} keycloakRole - Keycloak role name to find
   * @returns {Promise<RoleMapping|null>} Found mapping or null
   *
   * @example
   * const mapping = await roleMappingService.getMappingByRole('ADMIN');
   */
  async getMappingByRole(keycloakRole) {
    if (!keycloakRole || typeof keycloakRole !== 'string') {
      return null;
    }

    try {
      const [mapping] = await strapi.entityService.findMany(CONTENT_TYPES.ROLE_MAPPING, {
        filters: { keycloakRole: keycloakRole.trim() },
        limit: 1,
      });

      return mapping || null;
    } catch (error) {
      strapi.log.error(`Failed to find mapping for role ${keycloakRole}:`, error.message);
      return null;
    }
  },

  /**
   * Creates or updates a single role mapping.
   *
   * @async
   * @param {string} keycloakRole - Keycloak role name
   * @param {number} strapiRole - Strapi role ID
   * @param {Object} [performedBy] - Admin user performing the action
   * @returns {Promise<RoleMapping>} Created or updated mapping
   * @throws {PluginError} If operation fails
   *
   * @example
   * await roleMappingService.upsertMapping('ADMIN', 1, { id: 1, email: 'admin@example.com' });
   */
  async upsertMapping(keycloakRole, strapiRole, performedBy = null) {
    this._validateMapping(keycloakRole, strapiRole);

    const auditLogService = this._getAuditLogService();
    const normalizedRole = keycloakRole.trim();

    try {
      // Check if mapping exists
      const existingMapping = await this.getMappingByRole(normalizedRole);

      if (existingMapping) {
        // Update existing mapping
        const updated = await strapi.documents(CONTENT_TYPES.ROLE_MAPPING).update({
          documentId: existingMapping.documentId,
          data: { strapiRole },
        });

        strapi.log.info(`Updated role mapping: ${normalizedRole} -> ${strapiRole}`);

        auditLogService.logMappingChange({
          action: AUDIT_ACTIONS.MAPPING_UPDATED,
          keycloakRole: normalizedRole,
          strapiRole,
          performedBy,
        });

        return updated;
      }

      // Create new mapping
      const created = await strapi.entityService.create(CONTENT_TYPES.ROLE_MAPPING, {
        data: {
          keycloakRole: normalizedRole,
          strapiRole,
        },
      });

      strapi.log.info(`Created role mapping: ${normalizedRole} -> ${strapiRole}`);

      auditLogService.logMappingChange({
        action: AUDIT_ACTIONS.MAPPING_CREATED,
        keycloakRole: normalizedRole,
        strapiRole,
        performedBy,
      });

      return created;
    } catch (error) {
      if (error.code && error.safeMessage) {
        throw error;
      }

      strapi.log.error(`Failed to upsert mapping for ${keycloakRole}:`, error.message);

      throw createSanitizedError(
        ERROR_CODES.ROLE_MAPPING_ERROR,
        `Failed to save mapping for ${keycloakRole}: ${error.message}`,
        'Failed to save role mapping.'
      );
    }
  },

  /**
   * Deletes a role mapping by Keycloak role name.
   *
   * @async
   * @param {string} keycloakRole - Keycloak role name to delete
   * @param {Object} [performedBy] - Admin user performing the action
   * @returns {Promise<boolean>} True if mapping was deleted
   *
   * @example
   * await roleMappingService.deleteMapping('VIEWER', { id: 1, email: 'admin@example.com' });
   */
  async deleteMapping(keycloakRole, performedBy = null) {
    if (!keycloakRole || typeof keycloakRole !== 'string') {
      return false;
    }

    const auditLogService = this._getAuditLogService();
    const normalizedRole = keycloakRole.trim();

    try {
      const existingMapping = await this.getMappingByRole(normalizedRole);

      if (!existingMapping) {
        strapi.log.debug(`No mapping found to delete for role: ${normalizedRole}`);
        return false;
      }

      await strapi.documents(CONTENT_TYPES.ROLE_MAPPING).delete({
        documentId: existingMapping.documentId,
      });

      strapi.log.info(`Deleted role mapping: ${normalizedRole}`);

      auditLogService.logMappingChange({
        action: AUDIT_ACTIONS.MAPPING_DELETED,
        keycloakRole: normalizedRole,
        strapiRole: existingMapping.strapiRole,
        performedBy,
      });

      return true;
    } catch (error) {
      strapi.log.error(`Failed to delete mapping for ${keycloakRole}:`, error.message);
      return false;
    }
  },

  /**
   * Deletes all role mappings.
   *
   * @async
   * @param {Object} [performedBy] - Admin user performing the action
   * @returns {Promise<number>} Number of mappings deleted
   */
  async deleteAllMappings(performedBy = null) {
    try {
      const result = await strapi.db.query(CONTENT_TYPES.ROLE_MAPPING).deleteMany({
        where: {
          id: { $notNull: true },
        },
      });

      const deletedCount = result?.count || 0;

      if (deletedCount > 0) {
        strapi.log.info(`Deleted ${deletedCount} role mappings`);
      }

      return deletedCount;
    } catch (error) {
      strapi.log.error('Failed to delete all mappings:', error.message);
      throw createSanitizedError(
        ERROR_CODES.ROLE_MAPPING_ERROR,
        `Failed to delete all mappings: ${error.message}`,
        'Failed to delete role mappings.'
      );
    }
  },

  /**
   * Gets the count of role mappings.
   *
   * @async
   * @returns {Promise<number>} Number of mappings
   */
  async count() {
    try {
      return await strapi.entityService.count(CONTENT_TYPES.ROLE_MAPPING, {});
    } catch (error) {
      strapi.log.error('Failed to count role mappings:', error.message);
      return 0;
    }
  },

  /**
   * Checks if a mapping exists for a Keycloak role.
   *
   * @async
   * @param {string} keycloakRole - Keycloak role name
   * @returns {Promise<boolean>} True if mapping exists
   */
  async mappingExists(keycloakRole) {
    const mapping = await this.getMappingByRole(keycloakRole);
    return mapping !== null;
  },
});

export default roleMappingService;
