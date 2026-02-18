/**
 * @fileoverview Authentication override controller for Keycloak SSO.
 * Replaces Strapi's default admin login with Keycloak OAuth2 authentication.
 * @module controllers/authOverrideController
 * @author Strapi Keycloak Passport Team
 */

'use strict';

import axios from 'axios';
import {
  PLUGIN_ID,
  PLUGIN_NAMESPACE,
  KEYCLOAK_ENDPOINTS,
  KEYCLOAK_PATHS,
  HTTP,
  OAUTH_SCOPES,
  SESSION,
  ERROR_CODES,
} from '../constants.js';
import { createSanitizedError, PluginError, extractSafeError } from '../utils/errors.js';

/**
 * @typedef {Object} KoaContext
 * @property {Object} request - Koa request object
 * @property {Object} state - Request state including user info
 * @property {Object} session - Koa session object
 * @property {Object} cookies - Cookie management
 * @property {Function} send - Send response function
 * @property {Function} badRequest - Send 400 response function
 * @property {Function} internalServerError - Send 500 response function
 */

/**
 * @typedef {Object} AuthCredentials
 * @property {string} email - User's email address
 * @property {string} password - User's password
 */

/**
 * @typedef {Object} KeycloakTokenResponse
 * @property {string} access_token - OAuth access token
 * @property {number} expires_in - Token lifetime in seconds
 * @property {string} token_type - Token type (Bearer)
 * @property {string} [refresh_token] - Optional refresh token
 */

/**
 * @typedef {Object} KeycloakUserInfo
 * @property {string} sub - Keycloak user ID
 * @property {string} email - User's email
 * @property {string} [preferred_username] - Preferred username
 * @property {string} [given_name] - First name
 * @property {string} [family_name] - Last name
 * @property {boolean} [email_verified] - Email verification status
 */

/**
 * Gets the plugin configuration.
 *
 * @returns {Object} Plugin configuration
 * @private
 */
const getConfig = () => strapi.config.get(PLUGIN_NAMESPACE);

/**
 * Gets the admin user service.
 *
 * @returns {Object} Admin user service
 * @private
 */
const getAdminUserService = () => strapi.plugin(PLUGIN_ID).service('adminUserService');

/**
 * Gets the audit log service.
 *
 * @returns {Object} Audit log service
 * @private
 */
const getAuditLogService = () => strapi.plugin(PLUGIN_ID).service('auditLogService');

/**
 * Gets the session manager from Strapi.
 *
 * @returns {Object|null} Session manager or null
 * @private
 */
const getSessionManager = () => strapi.sessionManager ?? null;

/**
 * Determines the auth path prefix based on Keycloak version.
 *
 * @returns {string} Auth path prefix
 * @private
 */
const getAuthPrefix = () => {
  const config = getConfig();
  return config.KEYCLOAK_LEGACY_MODE
    ? KEYCLOAK_PATHS.LEGACY_AUTH_PREFIX
    : KEYCLOAK_PATHS.MODERN_AUTH_PREFIX;
};

/**
 * Builds a Keycloak endpoint URL.
 *
 * @param {string} endpointTemplate - Endpoint template
 * @returns {string} Full endpoint URL
 * @private
 */
const buildEndpointUrl = (endpointTemplate) => {
  const config = getConfig();
  const authPrefix = getAuthPrefix();

  let url = config.KEYCLOAK_AUTH_URL.replace(/\/+$/, '');
  url += authPrefix;
  url += endpointTemplate.replace('{realm}', config.KEYCLOAK_REALM);

  return url;
};

/**
 * Gets cookie options base configuration.
 *
 * @param {boolean} [secureRequest] - Whether request is secure
 * @returns {Object} Base cookie options
 * @private
 */
const getBaseCookieOptions = (secureRequest) => {
  const configuredSecure = strapi.config.get('admin.auth.cookie.secure');
  const isProduction = process.env.NODE_ENV === 'production';

  const domain = strapi.config.get('admin.auth.cookie.domain') ||
                 strapi.config.get('admin.auth.domain');
  const path = strapi.config.get('admin.auth.cookie.path', '/admin');
  const sameSite = strapi.config.get('admin.auth.cookie.sameSite') ?? 'lax';

  let isSecure;
  if (typeof configuredSecure === 'boolean') {
    isSecure = configuredSecure;
  } else if (secureRequest !== undefined) {
    isSecure = isProduction && secureRequest;
  } else {
    isSecure = isProduction;
  }

  return {
    httpOnly: true,
    secure: isSecure,
    overwrite: true,
    domain,
    path,
    sameSite,
    maxAge: undefined,
  };
};

/**
 * Builds cookie options with proper security settings.
 *
 * @param {string} type - Token type ('refresh' or 'session')
 * @param {string} [absoluteExpiresAtISO] - Absolute expiry timestamp
 * @param {boolean} [secureRequest] - Whether request is secure
 * @returns {Object} Cookie options
 * @private
 */
const buildCookieOptions = (type, absoluteExpiresAtISO, secureRequest) => {
  const baseOptions = getBaseCookieOptions(secureRequest);

  if (type === 'session') {
    return baseOptions;
  }

  // Calculate expiry for refresh token
  const idleSeconds = Number(
    strapi.config.get(
      'admin.auth.sessions.idleRefreshTokenLifespan',
      SESSION.IDLE_REFRESH_TOKEN_LIFESPAN
    )
  );

  const now = Date.now();
  const idleExpiry = now + idleSeconds * 1000;
  const absoluteExpiry = absoluteExpiresAtISO
    ? new Date(absoluteExpiresAtISO).getTime()
    : idleExpiry;
  const chosen = new Date(Math.min(idleExpiry, absoluteExpiry));

  return {
    ...baseOptions,
    expires: chosen,
    maxAge: Math.max(0, chosen.getTime() - now),
  };
};

/**
 * Extracts device parameters from request body.
 *
 * @param {Object} requestBody - Request body
 * @returns {Object} Device parameters
 * @private
 */
const extractDeviceParams = (requestBody) => {
  const body = requestBody ?? {};
  const deviceId = body.deviceId || crypto.randomUUID();
  const rememberMe = Boolean(body.rememberMe);

  return { deviceId, rememberMe };
};

/**
 * Extracts and validates credentials from request.
 *
 * @param {KoaContext} ctx - Koa context
 * @returns {AuthCredentials} Validated credentials
 * @throws {PluginError} If credentials are invalid
 * @private
 */
const extractCredentials = (ctx) => {
  const rawBody = ctx.request?.body || {};
  const email = rawBody.email;
  const password = rawBody.password;

  const isEmailValid = typeof email === 'string' && email.trim().length > 0;
  const isPasswordValid = typeof password === 'string' && password.trim().length > 0;

  if (!isEmailValid || !isPasswordValid) {
    throw createSanitizedError(
      ERROR_CODES.INVALID_PAYLOAD,
      `Invalid credentials provided: email=${isEmailValid}, password=${isPasswordValid}`,
      'Missing or invalid email/password.',
      { hasEmail: isEmailValid, hasPassword: isPasswordValid }
    );
  }

  return {
    email: email.trim(),
    password: password.trim(),
  };
};

/**
 * Requests an access token from Keycloak using password grant.
 *
 * @param {AuthCredentials} credentials - User credentials
 * @returns {Promise<KeycloakTokenResponse>} Token response
 * @throws {PluginError} If token request fails
 * @private
 */
const requestKeycloakToken = async (credentials) => {
  const config = getConfig();
  const tokenUrl = buildEndpointUrl(KEYCLOAK_ENDPOINTS.TOKEN);

  try {
    const response = await axios.post(
      tokenUrl,
      new URLSearchParams({
        client_id: config.KEYCLOAK_CLIENT_ID,
        client_secret: config.KEYCLOAK_CLIENT_SECRET,
        username: credentials.email,
        password: credentials.password,
        grant_type: HTTP.GRANT_TYPES.PASSWORD,
        scope: OAUTH_SCOPES.DEFAULT,
      }).toString(),
      {
        headers: {
          [HTTP.HEADERS.CONTENT_TYPE]: HTTP.CONTENT_TYPES.FORM_URLENCODED,
        },
      }
    );

    const tokenData = response.data;

    if (!tokenData?.access_token) {
      throw createSanitizedError(
        ERROR_CODES.KEYCLOAK_TOKEN_ERROR,
        'Keycloak returned empty access_token',
        'Authentication failed.'
      );
    }

    return tokenData;
  } catch (error) {
    if (error instanceof PluginError) {
      throw error;
    }

    strapi.log.error('Keycloak token request failed:', {
      status: error.response?.status,
      data: error.response?.data,
    });

    throw createSanitizedError(
      ERROR_CODES.KEYCLOAK_TOKEN_ERROR,
      `Token request failed: ${error.response?.status || error.message}`,
      'Invalid credentials.'
    );
  }
};

/**
 * Fetches user information from Keycloak.
 *
 * @param {string} accessToken - OAuth access token
 * @returns {Promise<KeycloakUserInfo>} User information
 * @throws {PluginError} If userinfo request fails
 * @private
 */
const fetchUserInfo = async (accessToken) => {
  const userInfoUrl = buildEndpointUrl(KEYCLOAK_ENDPOINTS.USERINFO);

  try {
    const response = await axios.get(userInfoUrl, {
      headers: {
        [HTTP.HEADERS.AUTHORIZATION]: `Bearer ${accessToken}`,
      },
    });

    return response.data || {};
  } catch (error) {
    strapi.log.error('Keycloak userinfo request failed:', {
      status: error.response?.status,
      data: error.response?.data,
    });

    throw createSanitizedError(
      ERROR_CODES.KEYCLOAK_USERINFO_ERROR,
      `Userinfo request failed: ${error.response?.status || error.message}`,
      'Failed to retrieve user information.'
    );
  }
};

/**
 * Builds the login response payload.
 *
 * @param {string} accessToken - Strapi access token
 * @param {Object} adminUser - Admin user object
 * @returns {Object} Login response
 * @private
 */
const buildLoginResponse = (accessToken, adminUser) => {
  const sanitizeUser = strapi.admin?.services?.user?.sanitizeUser || ((u) => u);

  return {
    data: {
      token: accessToken,
      accessToken,
      user: sanitizeUser(adminUser),
    },
  };
};

/**
 * Handles login errors with proper logging and response.
 *
 * @param {KoaContext} ctx - Koa context
 * @param {Error} error - Error that occurred
 * @param {string} [email] - User email for audit logging
 * @private
 */
const handleLoginError = async (ctx, error, email) => {
  const auditLogService = getAuditLogService();
  const safeError = extractSafeError(error);

  strapi.log.error(`Admin authentication failed [${safeError.code}]:`, error.message);

  // Log failed login attempt (non-blocking)
  if (email) {
    auditLogService.logLoginFailure({ email, reason: safeError.message }, ctx);
  }

  ctx.badRequest('Invalid credentials', {
    error: {
      status: 400,
      name: 'ApplicationError',
      code: safeError.code,
      message: 'Invalid credentials',
    },
  });
};

/**
 * Authentication override controller.
 * Handles Keycloak-based admin authentication.
 */
const AuthOverrideController = {
  /**
   * Authenticates an admin user via Keycloak OAuth2 password grant.
   * Replaces Strapi's default /admin/login endpoint.
   *
   * @async
   * @param {KoaContext} ctx - Koa context
   * @returns {Promise<void>}
   *
   * @example
   * // POST /admin/login
   * // Body: { email: "user@example.com", password: "secret", rememberMe: true }
   * // Response: { data: { token: "...", user: {...} } }
   */
  async login(ctx) {
    let credentials = null;

    try {
      // Extract and validate credentials
      credentials = extractCredentials(ctx);

      strapi.log.info(`Authenticating ${credentials.email} via Keycloak Passport...`);

      // 1. Authenticate with Keycloak
      const tokenPayload = await requestKeycloakToken(credentials);
      const keycloakUserInfo = await fetchUserInfo(tokenPayload.access_token);

      // 2. Sync/resolve admin user
      const adminUserService = getAdminUserService();
      const adminUser = await adminUserService.findOrCreate(keycloakUserInfo, ctx);

      // 3. Set user on context
      ctx.state.user = adminUser;

      // 4. Generate Strapi session tokens
      const sessionManager = getSessionManager();
      if (!sessionManager) {
        strapi.log.error('Admin session manager is not available');
        return ctx.internalServerError();
      }

      const userId = String(adminUser.id);
      const { deviceId, rememberMe } = extractDeviceParams(ctx.request.body);

      const {
        token: refreshToken,
        absoluteExpiresAt,
      } = await sessionManager('admin').generateRefreshToken(userId, deviceId, {
        type: rememberMe ? 'refresh' : 'session',
      });

      // 5. Set refresh token cookie
      const cookieOptions = buildCookieOptions(
        rememberMe ? 'refresh' : 'session',
        absoluteExpiresAt,
        ctx.request.secure
      );

      ctx.cookies.set(SESSION.REFRESH_COOKIE_NAME, refreshToken, cookieOptions);

      // 6. Generate access token
      const accessResult = await sessionManager('admin').generateAccessToken(refreshToken);
      if ('error' in accessResult) {
        strapi.log.error('Failed to generate access token', accessResult);
        return ctx.internalServerError();
      }

      const { token: accessToken } = accessResult;

      // 7. Attach admin to context/session
      ctx.state.admin = adminUser;
      ctx.session = {
        ...(ctx.session || {}),
        user: adminUser,
        admin: { id: adminUser.id },
      };

      strapi.log.info(`${credentials.email} successfully authenticated via Keycloak.`);

      // 8. Log successful login (non-blocking)
      const auditLogService = getAuditLogService();
      auditLogService.logLoginSuccess({
        email: credentials.email,
        keycloakUserId: keycloakUserInfo.sub,
        userId: String(adminUser.id),
        roles: adminUser.roles?.map((r) => r?.name).filter(Boolean) || [],
      }, ctx);

      // 9. Send response
      ctx.body = buildLoginResponse(accessToken, adminUser);
    } catch (error) {
      await handleLoginError(ctx, error, credentials?.email);
    }
  },
};

export default AuthOverrideController;
