/**
 * @fileoverview Error utilities for the Strapi Keycloak Passport plugin.
 * Provides structured error creation, sanitization, and handling patterns.
 * @module utils/errors
 * @author Strapi Keycloak Passport Team
 */

import { ERROR_CODES } from '../constants.js';

/**
 * Custom error class for plugin-specific errors.
 * Extends native Error with additional properties for structured error handling.
 *
 * @class PluginError
 * @extends Error
 */
export class PluginError extends Error {
  /**
   * Creates a new PluginError instance.
   *
   * @param {string} code - Error code from ERROR_CODES constant
   * @param {string} message - Human-readable error message
   * @param {string} [safeMessage] - Client-safe message (defaults to message)
   * @param {Object} [details] - Additional error details (internal only)
   */
  constructor(code, message, safeMessage = null, details = null) {
    super(message);

    /** @type {string} Error code identifier */
    this.code = code;

    /** @type {string} Error name for identification */
    this.name = 'PluginError';

    /** @type {string} Client-safe message without sensitive details */
    this.safeMessage = safeMessage || message;

    /** @type {Object|null} Internal details for logging */
    this.details = details;

    /** @type {number} Timestamp when error occurred */
    this.timestamp = Date.now();

    // Capture stack trace, excluding constructor call
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, PluginError);
    }
  }

  /**
   * Converts error to a client-safe JSON representation.
   * Excludes sensitive internal details.
   *
   * @returns {Object} Sanitized error object
   */
  toSafeJSON() {
    return {
      error: {
        code: this.code,
        message: this.safeMessage,
        timestamp: this.timestamp,
      },
    };
  }

  /**
   * Converts error to full JSON representation for logging.
   * Includes all details for debugging purposes.
   *
   * @returns {Object} Complete error object
   */
  toJSON() {
    return {
      code: this.code,
      name: this.name,
      message: this.message,
      safeMessage: this.safeMessage,
      details: this.details,
      timestamp: this.timestamp,
      stack: this.stack,
    };
  }
}

/**
 * Creates a sanitized error that separates internal and client-facing messages.
 * Use this pattern to log detailed errors internally while returning safe messages to clients.
 *
 * @param {string} code - Error code from ERROR_CODES constant
 * @param {string} internalMessage - Detailed message for internal logging
 * @param {string} clientMessage - Safe message to return to clients
 * @param {Object} [details] - Additional context for logging
 * @returns {PluginError} Configured error instance
 *
 * @example
 * throw createSanitizedError(
 *   ERROR_CODES.KEYCLOAK_TOKEN_ERROR,
 *   `Token fetch failed for client ${clientId}: 403 Forbidden`,
 *   'Failed to authenticate with Keycloak.'
 * );
 */
export const createSanitizedError = (code, internalMessage, clientMessage, details = null) => {
  return new PluginError(code, internalMessage, clientMessage, details);
};

/**
 * Creates a configuration error for missing or invalid plugin settings.
 *
 * @param {string} message - Description of the configuration issue
 * @param {string[]} [missingKeys] - List of missing configuration keys
 * @returns {PluginError} Configuration error instance
 *
 * @example
 * throw createConfigError('Plugin configuration is incomplete', ['KEYCLOAK_AUTH_URL']);
 */
export const createConfigError = (message, missingKeys = []) => {
  return new PluginError(
    ERROR_CODES.INVALID_CONFIGURATION,
    `Configuration error: ${message}. Missing: ${missingKeys.join(', ')}`,
    'Plugin configuration is invalid. Contact administrator.',
    { missingKeys }
  );
};

/**
 * Creates a Keycloak connection error.
 *
 * @param {string} operation - The operation that failed (e.g., 'fetch token')
 * @param {Error|Object} originalError - The original error from axios/fetch
 * @returns {PluginError} Connection error instance
 */
export const createKeycloakError = (operation, originalError) => {
  const status = originalError?.response?.status || 'unknown';
  const responseData = originalError?.response?.data || originalError?.message;

  return new PluginError(
    ERROR_CODES.KEYCLOAK_CONNECTION_ERROR,
    `Keycloak ${operation} failed [${status}]: ${JSON.stringify(responseData)}`,
    'Unable to communicate with authentication server.',
    {
      operation,
      status,
      response: responseData,
    }
  );
};

/**
 * Creates a permission denied error.
 *
 * @param {string} action - The action that was denied
 * @param {string} [resource] - The resource being accessed
 * @returns {PluginError} Permission error instance
 */
export const createPermissionError = (action, resource = null) => {
  const resourceInfo = resource ? ` on ${resource}` : '';

  return new PluginError(
    ERROR_CODES.PERMISSION_DENIED,
    `Permission denied: ${action}${resourceInfo}`,
    'You do not have permission to perform this action.',
    { action, resource }
  );
};

/**
 * Creates a validation error for invalid input data.
 *
 * @param {string} field - The field that failed validation
 * @param {string} reason - Why the validation failed
 * @returns {PluginError} Validation error instance
 */
export const createValidationError = (field, reason) => {
  return new PluginError(
    ERROR_CODES.INVALID_PAYLOAD,
    `Validation failed for ${field}: ${reason}`,
    `Invalid value for ${field}.`,
    { field, reason }
  );
};

/**
 * Wraps an operation with error handling and logging.
 * Catches errors, logs them with context, and re-throws as PluginError.
 *
 * @param {Function} operation - Async function to execute
 * @param {Object} context - Context for error logging
 * @param {string} context.operation - Name of the operation
 * @param {string} context.errorCode - Error code to use on failure
 * @param {string} context.clientMessage - Message to return to clients
 * @param {Object} strapi - Strapi instance for logging
 * @returns {Promise<*>} Result of the operation
 * @throws {PluginError} On operation failure
 *
 * @example
 * const result = await withErrorHandling(
 *   () => axios.get(url),
 *   {
 *     operation: 'fetchUserInfo',
 *     errorCode: ERROR_CODES.KEYCLOAK_USERINFO_ERROR,
 *     clientMessage: 'Failed to retrieve user information.'
 *   },
 *   strapi
 * );
 */
export const withErrorHandling = async (operation, context, strapi) => {
  try {
    return await operation();
  } catch (error) {
    // If already a PluginError, re-throw as-is
    if (error instanceof PluginError) {
      strapi.log.error(`[${error.code}] ${error.message}`, error.details);
      throw error;
    }

    // Wrap unknown errors
    const pluginError = new PluginError(
      context.errorCode || ERROR_CODES.INTERNAL_ERROR,
      `${context.operation} failed: ${error.message}`,
      context.clientMessage || 'An unexpected error occurred.',
      {
        originalError: error.message,
        stack: error.stack,
      }
    );

    strapi.log.error(`[${pluginError.code}] ${pluginError.message}`, pluginError.details);
    throw pluginError;
  }
};

/**
 * Extracts a safe error response from any error type.
 * Use this in controllers to return consistent error responses.
 *
 * @param {Error} error - Any error instance
 * @returns {Object} Safe error response object
 *
 * @example
 * try {
 *   await someOperation();
 * } catch (error) {
 *   return ctx.badRequest(extractSafeError(error).message);
 * }
 */
export const extractSafeError = (error) => {
  if (error instanceof PluginError) {
    return error.toSafeJSON().error;
  }

  return {
    code: ERROR_CODES.INTERNAL_ERROR,
    message: 'An unexpected error occurred.',
    timestamp: Date.now(),
  };
};

/**
 * Checks if an error is a specific type of PluginError.
 *
 * @param {Error} error - Error to check
 * @param {string} code - Error code to match
 * @returns {boolean} True if error matches the code
 */
export const isErrorCode = (error, code) => {
  if (!error) {
    return false;
  }

  return error instanceof PluginError && error.code === code;
};

/**
 * Creates an internal error for unexpected failures.
 *
 * @param {string} context - What was happening when the error occurred
 * @param {Error} [originalError] - The original error if available
 * @returns {PluginError} Internal error instance
 */
export const createInternalError = (context, originalError = null) => {
  return new PluginError(
    ERROR_CODES.INTERNAL_ERROR,
    `Internal error during ${context}: ${originalError?.message || 'Unknown cause'}`,
    'An unexpected error occurred. Please try again later.',
    originalError ? { originalMessage: originalError.message, stack: originalError.stack } : null
  );
};

export default {
  PluginError,
  createSanitizedError,
  createConfigError,
  createKeycloakError,
  createPermissionError,
  createValidationError,
  createInternalError,
  withErrorHandling,
  extractSafeError,
  isErrorCode,
};
