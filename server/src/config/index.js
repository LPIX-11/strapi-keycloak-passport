/**
 * @fileoverview Plugin configuration schema and validation.
 * Defines default values and validates required configuration options.
 * @module config
 * @author Strapi Keycloak Passport Team
 */

import {
  REQUIRED_CONFIG_KEYS,
  DEFAULT_CONFIG,
  VALIDATION,
  ROLE_DEFAULTS,
} from '../constants.js';

/**
 * @typedef {Object} RoleConfigs
 * @property {number} defaultRoleId - Default Strapi role ID when no mapping exists
 * @property {string[]} excludedRoles - Keycloak roles to exclude from mapping
 */

/**
 * @typedef {Object} PluginConfig
 * @property {string} KEYCLOAK_AUTH_URL - Base URL of the Keycloak server (e.g., https://keycloak.example.com)
 * @property {string} KEYCLOAK_REALM - Keycloak realm name
 * @property {string} KEYCLOAK_CLIENT_ID - OAuth client ID
 * @property {string} KEYCLOAK_CLIENT_SECRET - OAuth client secret
 * @property {boolean} [KEYCLOAK_LEGACY_MODE] - Use legacy /auth prefix for Keycloak < 17
 * @property {RoleConfigs} roleConfigs - Role mapping configuration
 */

/**
 * Validates that a string is a valid URL.
 *
 * @param {string} url - URL to validate
 * @returns {boolean} True if valid URL
 */
const isValidUrl = (url) => {
  if (!url || typeof url !== 'string') {
    return false;
  }

  return VALIDATION.URL_PATTERN.test(url.trim());
};

/**
 * Validates that a string is a valid realm name.
 *
 * @param {string} realm - Realm name to validate
 * @returns {boolean} True if valid realm name
 */
const isValidRealm = (realm) => {
  if (!realm || typeof realm !== 'string') {
    return false;
  }

  return VALIDATION.REALM_NAME_PATTERN.test(realm.trim());
};

/**
 * Normalizes the auth URL by removing trailing slashes.
 *
 * @param {string} url - URL to normalize
 * @returns {string} Normalized URL
 */
const normalizeUrl = (url) => {
  if (!url || typeof url !== 'string') {
    return '';
  }

  return url.trim().replace(/\/+$/, '');
};

/**
 * Plugin configuration export.
 */
export default {
  /**
   * Default configuration values.
   * These are merged with user-provided configuration.
   * @type {PluginConfig}
   */
  default: {
    KEYCLOAK_AUTH_URL: DEFAULT_CONFIG.KEYCLOAK_AUTH_URL,
    KEYCLOAK_REALM: DEFAULT_CONFIG.KEYCLOAK_REALM,
    KEYCLOAK_CLIENT_ID: DEFAULT_CONFIG.KEYCLOAK_CLIENT_ID,
    KEYCLOAK_CLIENT_SECRET: DEFAULT_CONFIG.KEYCLOAK_CLIENT_SECRET,
    KEYCLOAK_LEGACY_MODE: DEFAULT_CONFIG.KEYCLOAK_LEGACY_MODE,
    roleConfigs: {
      defaultRoleId: ROLE_DEFAULTS.DEFAULT_ROLE_ID,
      excludedRoles: [...ROLE_DEFAULTS.DEFAULT_EXCLUDED_ROLES],
    },
  },

  /**
   * Configuration validator.
   * Called during plugin initialization to ensure required values are present.
   *
   * @param {PluginConfig} config - Configuration to validate
   * @throws {Error} If configuration is invalid
   */
  validator(config) {
    // Check for required keys
    const missingKeys = REQUIRED_CONFIG_KEYS.filter((key) => {
      const value = config[key];
      return typeof value !== 'string' || value.trim().length === 0;
    });

    if (missingKeys.length > 0) {
      throw new Error(
        `Missing required Keycloak Passport configuration: ${missingKeys.join(', ')}. ` +
        'Please configure these values in your plugin settings.'
      );
    }

    // Validate KEYCLOAK_AUTH_URL format
    if (!isValidUrl(config.KEYCLOAK_AUTH_URL)) {
      throw new Error(
        `Invalid KEYCLOAK_AUTH_URL: "${config.KEYCLOAK_AUTH_URL}". ` +
        'Must be a valid HTTP(S) URL (e.g., https://keycloak.example.com).'
      );
    }

    // Validate KEYCLOAK_REALM format
    if (!isValidRealm(config.KEYCLOAK_REALM)) {
      throw new Error(
        `Invalid KEYCLOAK_REALM: "${config.KEYCLOAK_REALM}". ` +
        'Must contain only letters, numbers, hyphens, and underscores.'
      );
    }

    // Validate roleConfigs if provided
    if (config.roleConfigs) {
      const { defaultRoleId, excludedRoles } = config.roleConfigs;

      // Validate defaultRoleId
      if (defaultRoleId !== undefined) {
        if (typeof defaultRoleId !== 'number' || defaultRoleId < 1) {
          throw new Error(
            `Invalid roleConfigs.defaultRoleId: ${defaultRoleId}. ` +
            'Must be a positive integer.'
          );
        }
      }

      // Validate excludedRoles
      if (excludedRoles !== undefined) {
        if (!Array.isArray(excludedRoles)) {
          throw new Error(
            'Invalid roleConfigs.excludedRoles. Must be an array of strings.'
          );
        }

        const invalidRoles = excludedRoles.filter(
          (role) => typeof role !== 'string' || role.trim().length === 0
        );

        if (invalidRoles.length > 0) {
          throw new Error(
            'Invalid entries in roleConfigs.excludedRoles. All entries must be non-empty strings.'
          );
        }
      }
    }

    // Validate KEYCLOAK_LEGACY_MODE if provided
    if (config.KEYCLOAK_LEGACY_MODE !== undefined) {
      if (typeof config.KEYCLOAK_LEGACY_MODE !== 'boolean') {
        throw new Error(
          `Invalid KEYCLOAK_LEGACY_MODE: ${config.KEYCLOAK_LEGACY_MODE}. ` +
          'Must be a boolean (true for Keycloak < 17, false for Keycloak 17+).'
        );
      }
    }

    // Normalize URL (remove trailing slashes)
    config.KEYCLOAK_AUTH_URL = normalizeUrl(config.KEYCLOAK_AUTH_URL);

    // Log successful validation
    console.log('[strapi-keycloak-passport] Configuration validated successfully');
    console.log(`[strapi-keycloak-passport] Server: ${config.KEYCLOAK_AUTH_URL}`);
    console.log(`[strapi-keycloak-passport] Realm: ${config.KEYCLOAK_REALM}`);
    console.log(`[strapi-keycloak-passport] Legacy mode: ${config.KEYCLOAK_LEGACY_MODE ? 'Yes (Keycloak < 17)' : 'No (Keycloak 17+)'}`);
  },
};
