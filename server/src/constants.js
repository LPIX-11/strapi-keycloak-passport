/**
 * @fileoverview Centralized constants for the Strapi Keycloak Passport plugin.
 * All magic values, configuration defaults, and shared constants are defined here.
 * @module constants
 * @author Strapi Keycloak Passport Team
 */

/**
 * Plugin identifier used throughout Strapi's service locator.
 * @constant {string}
 */
export const PLUGIN_ID = 'strapi-keycloak-passport';

/**
 * Full plugin namespace for Strapi's config and service resolution.
 * @constant {string}
 */
export const PLUGIN_NAMESPACE = `plugin::${PLUGIN_ID}`;

/**
 * Content type UIDs for plugin-managed entities.
 * @constant {Object}
 * @property {string} ROLE_MAPPING - UID for role mapping content type
 * @property {string} AUDIT_LOG - UID for audit log content type
 */
export const CONTENT_TYPES = Object.freeze({
  ROLE_MAPPING: `${PLUGIN_NAMESPACE}.role-mapping`,
  AUDIT_LOG: `${PLUGIN_NAMESPACE}.audit-log`,
});

/**
 * Service identifiers for dependency injection.
 * @constant {Object}
 * @property {string} KEYCLOAK - Keycloak API service
 * @property {string} ADMIN_USER - Admin user management service
 * @property {string} ROLE_MAPPING - Role mapping service
 * @property {string} TOKEN_CACHE - Token caching service
 * @property {string} AUDIT_LOG - Audit logging service
 */
export const SERVICES = Object.freeze({
  KEYCLOAK: `${PLUGIN_NAMESPACE}.keycloakService`,
  ADMIN_USER: `${PLUGIN_NAMESPACE}.adminUserService`,
  ROLE_MAPPING: `${PLUGIN_NAMESPACE}.roleMappingService`,
  TOKEN_CACHE: `${PLUGIN_NAMESPACE}.tokenCacheService`,
  AUDIT_LOG: `${PLUGIN_NAMESPACE}.auditLogService`,
});

/**
 * Keycloak URL path configurations for different server versions.
 * @constant {Object}
 * @property {string} LEGACY_AUTH_PREFIX - Path prefix for Keycloak versions < 17
 * @property {string} MODERN_AUTH_PREFIX - Path prefix for Keycloak versions >= 17
 */
export const KEYCLOAK_PATHS = Object.freeze({
  LEGACY_AUTH_PREFIX: '/auth',
  MODERN_AUTH_PREFIX: '',
});

/**
 * Keycloak API endpoint templates.
 * Use with string interpolation: `${basePath}${KEYCLOAK_ENDPOINTS.TOKEN}`
 * @constant {Object}
 * @property {string} TOKEN - OAuth2 token endpoint path
 * @property {string} USERINFO - OpenID Connect userinfo endpoint path
 * @property {string} REALM_ROLES - Admin API realm roles endpoint template
 * @property {string} USER_REALM_ROLES - Admin API user role mappings endpoint template
 */
export const KEYCLOAK_ENDPOINTS = Object.freeze({
  TOKEN: '/realms/{realm}/protocol/openid-connect/token',
  USERINFO: '/realms/{realm}/protocol/openid-connect/userinfo',
  REALM_ROLES: '/admin/realms/{realm}/roles',
  USER_REALM_ROLES: '/admin/realms/{realm}/users/{userId}/role-mappings/realm',
});

/**
 * Token cache configuration values.
 * @constant {Object}
 * @property {number} EXPIRY_BUFFER_MS - Milliseconds before expiry to trigger refresh (60 seconds)
 * @property {number} DEFAULT_TOKEN_LIFETIME_MS - Default token lifetime if not specified (5 minutes)
 * @property {number} MIN_CACHE_TIME_MS - Minimum time to cache a token (30 seconds)
 */
export const TOKEN_CACHE = Object.freeze({
  EXPIRY_BUFFER_MS: 60 * 1000,
  DEFAULT_TOKEN_LIFETIME_MS: 5 * 60 * 1000,
  MIN_CACHE_TIME_MS: 30 * 1000,
});

/**
 * HTTP-related constants for API communication.
 * @constant {Object}
 * @property {Object} HEADERS - HTTP header names
 * @property {Object} CONTENT_TYPES - HTTP content type values
 * @property {Object} GRANT_TYPES - OAuth2 grant type values
 */
export const HTTP = Object.freeze({
  HEADERS: Object.freeze({
    CONTENT_TYPE: 'Content-Type',
    AUTHORIZATION: 'Authorization',
    ACCEPT: 'Accept',
  }),
  CONTENT_TYPES: Object.freeze({
    FORM_URLENCODED: 'application/x-www-form-urlencoded',
    JSON: 'application/json',
  }),
  GRANT_TYPES: Object.freeze({
    PASSWORD: 'password',
    CLIENT_CREDENTIALS: 'client_credentials',
    REFRESH_TOKEN: 'refresh_token',
  }),
});

/**
 * OAuth2 scopes requested from Keycloak.
 * @constant {Object}
 * @property {string} DEFAULT - Standard scope for user authentication
 * @property {string} ADMIN - Scope for admin operations (client credentials)
 */
export const OAUTH_SCOPES = Object.freeze({
  DEFAULT: 'email profile openid',
  ADMIN: '', // Client credentials flow doesn't use scopes
});

/**
 * Session configuration defaults.
 * @constant {Object}
 * @property {string} REFRESH_COOKIE_NAME - Name of the refresh token cookie
 * @property {number} MAX_REFRESH_TOKEN_LIFESPAN - Maximum refresh token lifetime in seconds (30 days)
 * @property {number} IDLE_REFRESH_TOKEN_LIFESPAN - Idle refresh token lifetime in seconds (14 days)
 * @property {number} MAX_SESSION_LIFESPAN - Maximum session lifetime in seconds (1 day)
 * @property {number} IDLE_SESSION_LIFESPAN - Idle session lifetime in seconds (2 hours)
 */
export const SESSION = Object.freeze({
  REFRESH_COOKIE_NAME: 'strapi_admin_refresh',
  MAX_REFRESH_TOKEN_LIFESPAN: 30 * 24 * 60 * 60,
  IDLE_REFRESH_TOKEN_LIFESPAN: 14 * 24 * 60 * 60,
  MAX_SESSION_LIFESPAN: 1 * 24 * 60 * 60,
  IDLE_SESSION_LIFESPAN: 2 * 60 * 60,
});

/**
 * Default role configuration values.
 * @constant {Object}
 * @property {number} DEFAULT_ROLE_ID - Default Strapi admin role ID
 * @property {string[]} DEFAULT_EXCLUDED_ROLES - Keycloak roles to exclude from mapping
 */
export const ROLE_DEFAULTS = Object.freeze({
  DEFAULT_ROLE_ID: 1,
  DEFAULT_EXCLUDED_ROLES: Object.freeze([
    'uma_authorization',
    'offline_access',
    'default-roles-master',
  ]),
});

/**
 * Audit log action types.
 * @constant {Object}
 * @property {string} LOGIN_SUCCESS - Successful user login
 * @property {string} LOGIN_FAILURE - Failed login attempt
 * @property {string} LOGOUT - User logout
 * @property {string} USER_CREATED - New admin user created
 * @property {string} USER_UPDATED - Admin user updated
 * @property {string} ROLE_ASSIGNED - Role assigned to user
 * @property {string} ROLE_REMOVED - Role removed from user
 * @property {string} MAPPING_CREATED - Role mapping created
 * @property {string} MAPPING_UPDATED - Role mapping updated
 * @property {string} MAPPING_DELETED - Role mapping deleted
 * @property {string} TOKEN_REFRESHED - Admin token refreshed
 */
export const AUDIT_ACTIONS = Object.freeze({
  LOGIN_SUCCESS: 'LOGIN_SUCCESS',
  LOGIN_FAILURE: 'LOGIN_FAILURE',
  LOGOUT: 'LOGOUT',
  USER_CREATED: 'USER_CREATED',
  USER_UPDATED: 'USER_UPDATED',
  ROLE_ASSIGNED: 'ROLE_ASSIGNED',
  ROLE_REMOVED: 'ROLE_REMOVED',
  MAPPING_CREATED: 'MAPPING_CREATED',
  MAPPING_UPDATED: 'MAPPING_UPDATED',
  MAPPING_DELETED: 'MAPPING_DELETED',
  TOKEN_REFRESHED: 'TOKEN_REFRESHED',
});

/**
 * Error codes for structured error handling.
 * @constant {Object}
 * @property {string} INVALID_PAYLOAD - Invalid request payload
 * @property {string} INVALID_CONFIGURATION - Plugin misconfiguration
 * @property {string} KEYCLOAK_CONNECTION_ERROR - Failed to connect to Keycloak
 * @property {string} KEYCLOAK_TOKEN_ERROR - Failed to obtain token
 * @property {string} KEYCLOAK_USERINFO_ERROR - Failed to fetch user info
 * @property {string} KEYCLOAK_ROLES_ERROR - Failed to fetch roles
 * @property {string} USER_SYNC_ERROR - Failed to sync user
 * @property {string} ROLE_MAPPING_ERROR - Role mapping operation failed
 * @property {string} PERMISSION_DENIED - Access denied
 * @property {string} INTERNAL_ERROR - Unexpected internal error
 */
export const ERROR_CODES = Object.freeze({
  INVALID_PAYLOAD: 'KC_INVALID_PAYLOAD',
  INVALID_CONFIGURATION: 'KC_INVALID_CONFIGURATION',
  KEYCLOAK_CONNECTION_ERROR: 'KC_CONNECTION_ERROR',
  KEYCLOAK_TOKEN_ERROR: 'KC_TOKEN_ERROR',
  KEYCLOAK_USERINFO_ERROR: 'KC_USERINFO_ERROR',
  KEYCLOAK_ROLES_ERROR: 'KC_ROLES_ERROR',
  USER_SYNC_ERROR: 'KC_USER_SYNC_ERROR',
  ROLE_MAPPING_ERROR: 'KC_ROLE_MAPPING_ERROR',
  PERMISSION_DENIED: 'KC_PERMISSION_DENIED',
  INTERNAL_ERROR: 'KC_INTERNAL_ERROR',
});

/**
 * Plugin permission action identifiers.
 * @constant {Object}
 * @property {string} ACCESS - Base plugin access
 * @property {string} VIEW_MAPPINGS - View role mappings
 * @property {string} MANAGE_MAPPINGS - Manage role mappings
 */
export const PERMISSIONS = Object.freeze({
  ACCESS: `${PLUGIN_NAMESPACE}.access`,
  VIEW_MAPPINGS: `${PLUGIN_NAMESPACE}.view-role-mappings`,
  MANAGE_MAPPINGS: `${PLUGIN_NAMESPACE}.manage-role-mappings`,
});

/**
 * Validation constraints for configuration and inputs.
 * @constant {Object}
 * @property {number} MIN_ROLE_NAME_LENGTH - Minimum role name length
 * @property {number} MAX_ROLE_NAME_LENGTH - Maximum role name length
 * @property {RegExp} URL_PATTERN - Valid URL pattern
 * @property {RegExp} REALM_NAME_PATTERN - Valid realm name pattern
 */
export const VALIDATION = Object.freeze({
  MIN_ROLE_NAME_LENGTH: 1,
  MAX_ROLE_NAME_LENGTH: 100,
  URL_PATTERN: /^https?:\/\/.+/i,
  REALM_NAME_PATTERN: /^[a-zA-Z0-9_-]+$/,
});

/**
 * Configuration keys expected in plugin config.
 * @constant {string[]}
 */
export const REQUIRED_CONFIG_KEYS = Object.freeze([
  'KEYCLOAK_AUTH_URL',
  'KEYCLOAK_REALM',
  'KEYCLOAK_CLIENT_ID',
  'KEYCLOAK_CLIENT_SECRET',
]);

/**
 * Default configuration values for the plugin.
 * @constant {Object}
 */
export const DEFAULT_CONFIG = Object.freeze({
  KEYCLOAK_AUTH_URL: '',
  KEYCLOAK_REALM: '',
  KEYCLOAK_CLIENT_ID: '',
  KEYCLOAK_CLIENT_SECRET: '',
  KEYCLOAK_LEGACY_MODE: false,
  roleConfigs: Object.freeze({
    defaultRoleId: ROLE_DEFAULTS.DEFAULT_ROLE_ID,
    excludedRoles: ROLE_DEFAULTS.DEFAULT_EXCLUDED_ROLES,
  }),
});
