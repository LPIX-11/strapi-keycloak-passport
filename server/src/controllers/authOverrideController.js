'use strict';

import axios from 'axios';

/**
 * --- Local copy of Strapi's session-auth helpers ---
 * (Taken from packages/core/admin/shared/utils/session-auth.ts)
 */

export const REFRESH_COOKIE_NAME = 'strapi_admin_refresh';

const DEFAULT_MAX_REFRESH_TOKEN_LIFESPAN = 30 * 24 * 60 * 60;
const DEFAULT_IDLE_REFRESH_TOKEN_LIFESPAN = 14 * 24 * 60 * 60;
const DEFAULT_MAX_SESSION_LIFESPAN = 1 * 24 * 60 * 60;
const DEFAULT_IDLE_SESSION_LIFESPAN = 2 * 60 * 60;

const getRefreshCookieOptions = (secureRequest) => {
  const configuredSecure = strapi.config.get('admin.auth.cookie.secure');
  const isProduction = process.env.NODE_ENV === 'production';

  const domain =
    strapi.config.get('admin.auth.cookie.domain') ||
    strapi.config.get('admin.auth.domain');
  const path = strapi.config.get('admin.auth.cookie.path', '/admin');

  const sameSite =
    strapi.config.get('admin.auth.cookie.sameSite') ?? 'lax';

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

const getLifespansForType = (type) => {
  if (type === 'refresh') {
    const idleSeconds = Number(
      strapi.config.get(
        'admin.auth.sessions.idleRefreshTokenLifespan',
        DEFAULT_IDLE_REFRESH_TOKEN_LIFESPAN
      )
    );
    const maxSeconds = Number(
      strapi.config.get(
        'admin.auth.sessions.maxRefreshTokenLifespan',
        DEFAULT_MAX_REFRESH_TOKEN_LIFESPAN
      )
    );

    return { idleSeconds, maxSeconds };
  }

  const idleSeconds = Number(
    strapi.config.get(
      'admin.auth.sessions.idleSessionLifespan',
      DEFAULT_IDLE_SESSION_LIFESPAN
    )
  );
  const maxSeconds = Number(
    strapi.config.get(
      'admin.auth.sessions.maxSessionLifespan',
      DEFAULT_MAX_SESSION_LIFESPAN
    )
  );

  return { idleSeconds, maxSeconds };
};

const buildCookieOptionsWithExpiry = (
  type,
  absoluteExpiresAtISO,
  secureRequest
) => {
  const base = getRefreshCookieOptions(secureRequest);
  if (type === 'session') {
    return base;
  }

  const { idleSeconds } = getLifespansForType('refresh');
  const now = Date.now();
  const idleExpiry = now + idleSeconds * 1000;
  const absoluteExpiry = absoluteExpiresAtISO
    ? new Date(absoluteExpiresAtISO).getTime()
    : idleExpiry;
  const chosen = new Date(Math.min(idleExpiry, absoluteExpiry));

  return {
    ...base,
    expires: chosen,
    maxAge: Math.max(0, chosen.getTime() - now),
  };
};

const getSessionManager = () => {
  const manager = strapi.sessionManager;
  return manager ?? null;
};

const extractDeviceParams = (requestBody) => {
  const body = (requestBody ?? {});
  const deviceId = body.deviceId || crypto.randomUUID();
  const rememberMe = Boolean(body.rememberMe);

  return { deviceId, rememberMe };
};

/**
 * --- Typedefs & constants ---
 */

/**
 * @typedef {Object} KoaContext
 * @property {{ body?: Record<string, unknown>, header?: Record<string, string> }} request
 * @property {Record<string, unknown>} state
 * @property {Record<string, unknown>|undefined} [session]
 * @property {(message: string, details?: unknown) => void} badRequest
 * @property {(body: unknown, status?: number) => void} send
 * @property {string} ip
 * @property {{ set: (name: string, value: string, options?: Record<string, unknown>) => void; get: (name: string) => string | undefined }} cookies
 */

/**
 * @typedef {Object} AuthCredentials
 * @property {string} email
 * @property {string} password
 */

/**
 * @typedef {Object} KeycloakPluginConfig
 * @property {string} KEYCLOAK_AUTH_URL
 * @property {string} KEYCLOAK_TOKEN_URL
 * @property {string} KEYCLOAK_USERINFO_URL
 * @property {string} KEYCLOAK_CLIENT_ID
 * @property {string} KEYCLOAK_CLIENT_SECRET
 */

/**
 * @typedef {Object} KeycloakTokenPayload
 * @property {string} access_token
 */

/**
 * @typedef {Object} AdminUser
 * @property {number|string} id
 * @property {string} email
 * @property {string} firstname
 * @property {string} lastname
 * @property {string|null} [username]
 * @property {boolean} [isActive]
 * @property {boolean} [blocked]
 * @property {string|Date} [createdAt]
 * @property {string|Date} [updatedAt]
 */

/**
 * Constant HTTP header names used by the controller.
 */
const HTTP_HEADERS = {
  CONTENT_TYPE: 'Content-Type',
  AUTHORIZATION: 'Authorization',
};

/**
 * Constant HTTP header values used by the controller.
 */
const HTTP_HEADER_VALUES = {
  FORM_URLENCODED: 'application/x-www-form-urlencoded',
};

/**
 * Default OAuth2 scope requested from Keycloak.
 */
const KEYCLOAK_DEFAULT_SCOPE = 'email profile openid';

/**
 * Structured error code identifiers used internally by the controller.
 */
const AUTH_ERROR_CODES = {
  INVALID_PAYLOAD: 'INVALID_PAYLOAD',
  INVALID_CONFIGURATION: 'INVALID_CONFIGURATION',
  KEYCLOAK_TOKEN_ERROR: 'KEYCLOAK_TOKEN_ERROR',
  KEYCLOAK_USERINFO_ERROR: 'KEYCLOAK_USERINFO_ERROR',
  JWT_ISSUE_ERROR: 'JWT_ISSUE_ERROR',
  INTERNAL_ERROR: 'INTERNAL_ERROR',
};

/**
 * Creates a standardized error object for the authentication flow.
 */
function createAuthError(code, message, details) {
  const error = new Error(message);
  error.code = code;
  if (details !== undefined) {
    error.details = details;
  }
  return error;
}

/**
 * Extracts and validates user credentials from the request context.
 */
function extractCredentials(ctx) {
  const rawBody = ctx.request?.body || {};
  const email = rawBody.email;
  const password = rawBody.password;

  const isEmailValid = typeof email === 'string' && email.trim().length > 0;
  const isPasswordValid = typeof password === 'string' && password.trim().length > 0;

  if (!isEmailValid || !isPasswordValid) {
    throw createAuthError(
      AUTH_ERROR_CODES.INVALID_PAYLOAD,
      'Missing or invalid email/password in request body.',
      { hasEmail: isEmailValid, hasPassword: isPasswordValid }
    );
  }

  return {
    email: email.trim(),
    password: password.trim(),
  };
}

/**
 * Resolves and validates the plugin configuration for Keycloak.
 */
function getKeycloakConfig() {
  const config = strapi.config.get('plugin::strapi-keycloak-passport') || {};

  const requiredKeys = [
    'KEYCLOAK_AUTH_URL',
    'KEYCLOAK_TOKEN_URL',
    'KEYCLOAK_USERINFO_URL',
    'KEYCLOAK_CLIENT_ID',
    'KEYCLOAK_CLIENT_SECRET',
  ];

  const missingKeys = requiredKeys.filter((key) => {
    const value = config[key];
    return typeof value !== 'string' || value.trim().length === 0;
  });

  if (missingKeys.length > 0) {
    throw createAuthError(
      AUTH_ERROR_CODES.INVALID_CONFIGURATION,
      'Keycloak plugin configuration is incomplete.',
      { missingKeys }
    );
  }

  return config;
}

/**
 * Requests an access token from Keycloak using password grant.
 */
async function requestKeycloakToken(credentials, config) {
  try {
    const tokenUrl = `${config.KEYCLOAK_AUTH_URL}${config.KEYCLOAK_TOKEN_URL}`;

    const requestBody = new URLSearchParams({
      client_id: config.KEYCLOAK_CLIENT_ID,
      client_secret: config.KEYCLOAK_CLIENT_SECRET,
      username: credentials.email,
      password: credentials.password,
      grant_type: 'password',
      scope: KEYCLOAK_DEFAULT_SCOPE,
    });

    const response = await axios.post(tokenUrl, requestBody.toString(), {
      headers: {
        [HTTP_HEADERS.CONTENT_TYPE]: HTTP_HEADER_VALUES.FORM_URLENCODED,
      },
    });

    const tokenPayload = response.data;

    if (!tokenPayload || typeof tokenPayload.access_token !== 'string') {
      throw createAuthError(
        AUTH_ERROR_CODES.KEYCLOAK_TOKEN_ERROR,
        'Keycloak token response is missing access_token.',
        { rawResponse: response.data }
      );
    }

    return tokenPayload;
  } catch (error) {
    strapi.log.error('🔴 Keycloak token request failed:', error?.response?.data || error.message);

    throw createAuthError(
      AUTH_ERROR_CODES.KEYCLOAK_TOKEN_ERROR,
      'Unable to obtain an access token from Keycloak.',
      error
    );
  }
}

/**
 * Fetches the authenticated user information from Keycloak.
 */
async function fetchKeycloakUserInfo(accessToken, config) {
  try {
    const userInfoUrl = `${config.KEYCLOAK_AUTH_URL}${config.KEYCLOAK_USERINFO_URL}`;

    const response = await axios.get(userInfoUrl, {
      headers: {
        [HTTP_HEADERS.AUTHORIZATION]: `Bearer ${accessToken}`,
      },
    });

    const userInfo = response.data || {};

    return userInfo;
  } catch (error) {
    strapi.log.error('🔴 Keycloak userinfo request failed:', error?.response?.data || error.message);

    throw createAuthError(
      AUTH_ERROR_CODES.KEYCLOAK_USERINFO_ERROR,
      'Unable to retrieve user information from Keycloak.',
      error
    );
  }
}

/**
 * Synchronizes the Keycloak user with the Strapi admin user model.
 */
async function synchronizeAdminUser(keycloakUserInfo) {
  const adminUser = await strapi
    .service('plugin::strapi-keycloak-passport.adminUserService')
    .findOrCreate(keycloakUserInfo);

  return adminUser;
}

/**
 * Attaches the authenticated admin user to the Koa context and session.
 */
function attachAdminToContext(ctx, adminUser) {
  ctx.state.admin = adminUser;
  ctx.state.user = adminUser;

  ctx.session = {
    ...(ctx.session || {}),
    user: adminUser,
    admin: { id: adminUser.id },
  };
}

/**
 * Builds the response payload for a successful login.
 * Same shape as core /admin/login.
 */
function buildLoginResponse(accessToken, adminUser) {
  const sanitizeUser =
    strapi.admin?.services?.user?.sanitizeUser || ((u) => u);

  return {
    data: {
      token: accessToken,
      accessToken,
      user: sanitizeUser(adminUser),
    },
  };
}

/**
 * Handles any error raised during the authentication flow.
 */
function handleLoginError(ctx, error) {
  const errorCode = error.code || AUTH_ERROR_CODES.INTERNAL_ERROR;

  strapi.log.error(
    `🔴 Admin authentication failed [${errorCode}]:`,
    error.details || error.message
  );

  ctx.badRequest('Invalid credentials', {
    error: {
      status: 400,
      name: error.name || 'ApplicationError',
      code: errorCode,
      message: 'Invalid credentials',
      details: error.details || {},
    },
  });
}

/**
 * AuthOverrideController
 *
 * Delegates admin authentication to Keycloak, then uses the SAME
 * session/token machinery as core /admin/login.
 */
const AuthOverrideController = {
  async login(ctx) {
    try {
      const credentials = extractCredentials(ctx);
      const config = getKeycloakConfig();

      strapi.log.info(`🔵 Authenticating ${credentials.email} via Keycloak Passport...`);

      // 1️⃣ Authenticate with Keycloak
      const tokenPayload = await requestKeycloakToken(credentials, config);
      const keycloakUserInfo = await fetchKeycloakUserInfo(tokenPayload.access_token, config);

      // 2️⃣ Sync / resolve admin user
      const adminUser = await synchronizeAdminUser(keycloakUserInfo);

      // 3️⃣ Put user on ctx.state like passport/local does
      ctx.state.user = adminUser;

      // 4️⃣ Use Strapi's session manager exactly like core /admin/login
      const sessionManager = getSessionManager();
      if (!sessionManager) {
        strapi.log.error('Admin session manager is not available');
        return ctx.internalServerError();
      }

      const userId = String(adminUser.id);
      const { deviceId, rememberMe } = extractDeviceParams(ctx.request.body || {});

      const {
        token: refreshToken,
        absoluteExpiresAt,
      } = await sessionManager('admin').generateRefreshToken(userId, deviceId, {
        type: rememberMe ? 'refresh' : 'session',
      });

      const cookieOptions = buildCookieOptionsWithExpiry(
        rememberMe ? 'refresh' : 'session',
        absoluteExpiresAt,
        ctx.request.secure
      );

      ctx.cookies.set(REFRESH_COOKIE_NAME, refreshToken, cookieOptions);

      const accessResult = await sessionManager('admin').generateAccessToken(refreshToken);
      if ('error' in accessResult) {
        strapi.log.error('Failed to generate access token from admin refresh token', accessResult);
        return ctx.internalServerError();
      }

      const { token: accessToken } = accessResult;

      // 5️⃣ Attach admin to context/session for downstream use
      attachAdminToContext(ctx, adminUser);

      strapi.log.info(`✅ ${credentials.email} successfully authenticated via Keycloak.`);

      // 6️⃣ Build response exactly like core /admin/login
      const responseBody = buildLoginResponse(accessToken, adminUser);
      ctx.body = responseBody;
    } catch (error) {
      handleLoginError(ctx, error);
    }
  },
};

export default AuthOverrideController;
