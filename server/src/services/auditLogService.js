/**
 * @fileoverview Audit logging service for tracking authentication events and actions.
 * Provides non-blocking audit trail functionality for compliance and debugging.
 * @module services/auditLogService
 * @author Strapi Keycloak Passport Team
 */

import { CONTENT_TYPES, AUDIT_ACTIONS } from '../constants.js';

/**
 * @typedef {Object} AuditLogEntry
 * @property {string} action - Action type from AUDIT_ACTIONS
 * @property {string} [userEmail] - Email of the user involved
 * @property {string} [userId] - Strapi user ID
 * @property {string} [keycloakUserId] - Keycloak user ID (sub claim)
 * @property {string} [ipAddress] - Client IP address
 * @property {string} [userAgent] - Client user agent string
 * @property {Object} [details] - Additional action-specific details
 * @property {number} [performedById] - ID of the admin performing the action
 * @property {string} [performedByEmail] - Email of the admin performing the action
 * @property {boolean} [success] - Whether the action succeeded
 * @property {string} [errorMessage] - Error message if action failed
 */

/**
 * @typedef {Object} AuditQueryOptions
 * @property {string} [action] - Filter by action type
 * @property {string} [userEmail] - Filter by user email
 * @property {string} [userId] - Filter by Strapi user ID
 * @property {string} [keycloakUserId] - Filter by Keycloak user ID
 * @property {boolean} [success] - Filter by success status
 * @property {Date} [startDate] - Filter entries after this date
 * @property {Date} [endDate] - Filter entries before this date
 * @property {number} [limit] - Maximum number of entries to return
 * @property {number} [offset] - Number of entries to skip
 * @property {string} [sortBy] - Field to sort by (default: createdAt)
 * @property {string} [sortOrder] - Sort order: 'asc' or 'desc' (default: desc)
 */

/**
 * Default pagination configuration.
 * @constant {Object}
 */
const PAGINATION_DEFAULTS = Object.freeze({
  LIMIT: 50,
  MAX_LIMIT: 500,
  OFFSET: 0,
});

/**
 * Audit log service factory.
 * Provides non-blocking audit logging with comprehensive tracking capabilities.
 *
 * @param {Object} params - Service parameters
 * @param {Object} params.strapi - Strapi instance
 * @returns {Object} Audit log service methods
 */
const auditLogService = ({ strapi }) => ({
  /**
   * Extracts client information from a Koa context.
   *
   * @param {Object} ctx - Koa context object
   * @returns {Object} Extracted client information
   * @private
   */
  _extractClientInfo(ctx) {
    if (!ctx) {
      return { ipAddress: null, userAgent: null };
    }

    // Get IP address, accounting for proxies
    const forwardedFor = ctx.request?.headers?.['x-forwarded-for'];
    const ipAddress = forwardedFor
      ? forwardedFor.split(',')[0].trim()
      : ctx.request?.ip || ctx.ip || null;

    // Get user agent
    const userAgent = ctx.request?.headers?.['user-agent'] || null;

    return {
      ipAddress: ipAddress?.substring(0, 45), // Max length constraint
      userAgent: userAgent?.substring(0, 500), // Max length constraint
    };
  },

  /**
   * Logs an audit entry to the database.
   * This method is non-blocking - failures are logged but don't interrupt the main flow.
   *
   * @param {AuditLogEntry} entry - The audit entry to log
   * @param {Object} [ctx] - Optional Koa context for extracting client info
   * @returns {Promise<Object|null>} The created audit log entry, or null on failure
   *
   * @example
   * await auditLogService.log({
   *   action: AUDIT_ACTIONS.LOGIN_SUCCESS,
   *   userEmail: 'user@example.com',
   *   keycloakUserId: 'abc-123',
   *   details: { roles: ['admin'] }
   * }, ctx);
   */
  async log(entry, ctx = null) {
    try {
      const clientInfo = this._extractClientInfo(ctx);

      /** @type {AuditLogEntry} */
      const auditEntry = {
        action: entry.action,
        userEmail: entry.userEmail || null,
        userId: entry.userId || null,
        keycloakUserId: entry.keycloakUserId || null,
        ipAddress: entry.ipAddress || clientInfo.ipAddress,
        userAgent: entry.userAgent || clientInfo.userAgent,
        details: entry.details || null,
        performedById: entry.performedById || null,
        performedByEmail: entry.performedByEmail || null,
        success: entry.success !== false,
        errorMessage: entry.errorMessage || null,
      };

      const result = await strapi.entityService.create(CONTENT_TYPES.AUDIT_LOG, {
        data: auditEntry,
      });

      strapi.log.debug(`Audit logged: ${entry.action} for ${entry.userEmail || 'unknown'}`);
      return result;
    } catch (error) {
      // Non-blocking: log the error but don't throw
      strapi.log.error('Failed to write audit log entry:', {
        error: error.message,
        entry: {
          action: entry.action,
          userEmail: entry.userEmail,
        },
      });
      return null;
    }
  },

  /**
   * Logs a successful login event.
   *
   * @param {Object} params - Login parameters
   * @param {string} params.email - User's email address
   * @param {string} params.keycloakUserId - Keycloak user ID
   * @param {string} [params.userId] - Strapi user ID
   * @param {string[]} [params.roles] - Assigned roles
   * @param {Object} [ctx] - Koa context
   * @returns {Promise<Object|null>} Created audit entry
   */
  async logLoginSuccess({ email, keycloakUserId, userId, roles }, ctx = null) {
    return this.log({
      action: AUDIT_ACTIONS.LOGIN_SUCCESS,
      userEmail: email,
      userId,
      keycloakUserId,
      success: true,
      details: { roles },
    }, ctx);
  },

  /**
   * Logs a failed login attempt.
   *
   * @param {Object} params - Login failure parameters
   * @param {string} params.email - Attempted email address
   * @param {string} params.reason - Reason for failure
   * @param {Object} [ctx] - Koa context
   * @returns {Promise<Object|null>} Created audit entry
   */
  async logLoginFailure({ email, reason }, ctx = null) {
    return this.log({
      action: AUDIT_ACTIONS.LOGIN_FAILURE,
      userEmail: email,
      success: false,
      errorMessage: reason,
    }, ctx);
  },

  /**
   * Logs a user creation event.
   *
   * @param {Object} params - User creation parameters
   * @param {string} params.email - New user's email
   * @param {string} params.userId - Created Strapi user ID
   * @param {string} params.keycloakUserId - Keycloak user ID
   * @param {number[]} params.roles - Assigned role IDs
   * @param {Object} [ctx] - Koa context
   * @returns {Promise<Object|null>} Created audit entry
   */
  async logUserCreated({ email, userId, keycloakUserId, roles }, ctx = null) {
    return this.log({
      action: AUDIT_ACTIONS.USER_CREATED,
      userEmail: email,
      userId,
      keycloakUserId,
      success: true,
      details: { roles },
    }, ctx);
  },

  /**
   * Logs a user update event.
   *
   * @param {Object} params - User update parameters
   * @param {string} params.email - User's email
   * @param {string} params.userId - Strapi user ID
   * @param {Object} params.changes - Fields that were updated
   * @param {Object} [ctx] - Koa context
   * @returns {Promise<Object|null>} Created audit entry
   */
  async logUserUpdated({ email, userId, changes }, ctx = null) {
    return this.log({
      action: AUDIT_ACTIONS.USER_UPDATED,
      userEmail: email,
      userId,
      success: true,
      details: { changes },
    }, ctx);
  },

  /**
   * Logs a role mapping change.
   *
   * @param {Object} params - Mapping change parameters
   * @param {string} params.action - Specific action (MAPPING_CREATED, etc.)
   * @param {string} params.keycloakRole - Keycloak role name
   * @param {number} params.strapiRole - Strapi role ID
   * @param {Object} params.performedBy - Admin who made the change
   * @param {number} params.performedBy.id - Admin user ID
   * @param {string} params.performedBy.email - Admin user email
   * @param {Object} [ctx] - Koa context
   * @returns {Promise<Object|null>} Created audit entry
   */
  async logMappingChange({ action, keycloakRole, strapiRole, performedBy }, ctx = null) {
    return this.log({
      action,
      success: true,
      performedById: performedBy?.id,
      performedByEmail: performedBy?.email,
      details: { keycloakRole, strapiRole },
    }, ctx);
  },

  /**
   * Queries audit log entries with filtering and pagination.
   *
   * @param {AuditQueryOptions} options - Query options
   * @returns {Promise<Object>} Query results with pagination info
   * @property {Object[]} data - Array of audit log entries
   * @property {Object} pagination - Pagination metadata
   *
   * @example
   * const results = await auditLogService.query({
   *   action: 'LOGIN_SUCCESS',
   *   startDate: new Date('2024-01-01'),
   *   limit: 100
   * });
   */
  async query(options = {}) {
    try {
      const {
        action,
        userEmail,
        userId,
        keycloakUserId,
        success,
        startDate,
        endDate,
        limit = PAGINATION_DEFAULTS.LIMIT,
        offset = PAGINATION_DEFAULTS.OFFSET,
        sortBy = 'createdAt',
        sortOrder = 'desc',
      } = options;

      // Build filters
      const filters = {};

      if (action) {
        filters.action = action;
      }

      if (userEmail) {
        filters.userEmail = { $containsi: userEmail };
      }

      if (userId) {
        filters.userId = userId;
      }

      if (keycloakUserId) {
        filters.keycloakUserId = keycloakUserId;
      }

      if (typeof success === 'boolean') {
        filters.success = success;
      }

      if (startDate || endDate) {
        filters.createdAt = {};
        if (startDate) {
          filters.createdAt.$gte = startDate;
        }
        if (endDate) {
          filters.createdAt.$lte = endDate;
        }
      }

      // Enforce maximum limit
      const effectiveLimit = Math.min(limit, PAGINATION_DEFAULTS.MAX_LIMIT);

      // Execute query
      const [entries, count] = await Promise.all([
        strapi.entityService.findMany(CONTENT_TYPES.AUDIT_LOG, {
          filters,
          sort: { [sortBy]: sortOrder },
          limit: effectiveLimit,
          offset,
        }),
        strapi.entityService.count(CONTENT_TYPES.AUDIT_LOG, { filters }),
      ]);

      return {
        data: entries,
        pagination: {
          total: count,
          limit: effectiveLimit,
          offset,
          hasMore: offset + entries.length < count,
        },
      };
    } catch (error) {
      strapi.log.error('Failed to query audit logs:', error.message);
      throw error;
    }
  },

  /**
   * Gets recent audit entries for a specific user.
   *
   * @param {string} userEmail - User's email address
   * @param {number} [limit=10] - Maximum entries to return
   * @returns {Promise<Object[]>} Array of audit log entries
   */
  async getByUser(userEmail, limit = 10) {
    const result = await this.query({
      userEmail,
      limit,
      sortBy: 'createdAt',
      sortOrder: 'desc',
    });

    return result.data;
  },

  /**
   * Gets recent failed login attempts.
   *
   * @param {number} [limit=50] - Maximum entries to return
   * @param {number} [withinHours=24] - Only include failures within this time window
   * @returns {Promise<Object[]>} Array of failed login entries
   */
  async getRecentFailures(limit = 50, withinHours = 24) {
    const startDate = new Date();
    startDate.setHours(startDate.getHours() - withinHours);

    const result = await this.query({
      action: AUDIT_ACTIONS.LOGIN_FAILURE,
      startDate,
      limit,
      sortBy: 'createdAt',
      sortOrder: 'desc',
    });

    return result.data;
  },

  /**
   * Counts failed login attempts for a specific email within a time window.
   * Useful for implementing rate limiting or account lockout.
   *
   * @param {string} email - Email address to check
   * @param {number} [withinMinutes=15] - Time window in minutes
   * @returns {Promise<number>} Number of failed attempts
   */
  async countRecentFailuresForEmail(email, withinMinutes = 15) {
    const startDate = new Date();
    startDate.setMinutes(startDate.getMinutes() - withinMinutes);

    try {
      const count = await strapi.entityService.count(CONTENT_TYPES.AUDIT_LOG, {
        filters: {
          action: AUDIT_ACTIONS.LOGIN_FAILURE,
          userEmail: email,
          createdAt: { $gte: startDate },
        },
      });

      return count;
    } catch (error) {
      strapi.log.error('Failed to count login failures:', error.message);
      return 0;
    }
  },

  /**
   * Deletes audit logs older than a specified number of days.
   * Use for maintenance and compliance with data retention policies.
   *
   * @param {number} daysToKeep - Number of days of logs to retain
   * @returns {Promise<number>} Number of entries deleted
   */
  async pruneOldEntries(daysToKeep) {
    if (daysToKeep < 1) {
      throw new Error('daysToKeep must be at least 1');
    }

    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - daysToKeep);

    try {
      const result = await strapi.db.query(CONTENT_TYPES.AUDIT_LOG).deleteMany({
        where: {
          createdAt: { $lt: cutoffDate },
        },
      });

      const deletedCount = result?.count || 0;

      if (deletedCount > 0) {
        strapi.log.info(`Pruned ${deletedCount} audit log entries older than ${daysToKeep} days`);
      }

      return deletedCount;
    } catch (error) {
      strapi.log.error('Failed to prune audit logs:', error.message);
      throw error;
    }
  },
});

export default auditLogService;
