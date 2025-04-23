'use strict';

import axios from 'axios';

/**
 * @module AuthOverrideController
 * @description Handles Keycloak authentication and synchronizes users with Strapi.
 */
export default {
  /**
   * Handles Keycloak login and synchronizes the user with Strapi.
   *
   * @async
   * @function login
   * @param {Object} ctx - Koa context.
   * @param {Object} ctx.request - Request object containing body data.
   * @param {Object} ctx.request.body - Request body data.
   * @param {string} ctx.request.body.email - The email address of the user attempting to log in.
   * @param {string} ctx.request.body.password - The password of the user attempting to log in.
   * @returns {Promise<Object>} The response containing JWT and user details.
   * @throws {Error} If authentication fails or credentials are invalid.
   */
  async login(ctx) {
    try {
      /** @type {string} */
      const email = ctx.request.body?.email;
      /** @type {string} */
      const password = ctx.request.body?.password;

      if (!email || !password) {
        return ctx.badRequest('Missing email or password');
      }

      /** @type {Object} */
      const config = strapi.config.get('plugin::strapi-keycloak-passport');
      strapi.log.info(`🔵 Authenticating ${email} via Keycloak Passport...`);

      // 🔑 Authenticate with Keycloak
      const tokenResponse = await axios.post(
        `${config.KEYCLOAK_AUTH_URL}${config.KEYCLOAK_TOKEN_URL}`,
        new URLSearchParams({
          client_id: config.KEYCLOAK_CLIENT_ID,
          client_secret: config.KEYCLOAK_CLIENT_SECRET,
          username: email,
          password,
          grant_type: 'password',
        }).toString(),
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
      );

      /** @type {string} */
      const access_token = tokenResponse.data.access_token;
      strapi.log.info(`✅ ${email} successfully authenticated via Keycloak.`);

      // 🔍 Fetch user details from Keycloak
      const userInfoResponse = await axios.get(
        `${config.KEYCLOAK_AUTH_URL}${config.KEYCLOAK_USERINFO_URL}`,
        { headers: { Authorization: `Bearer ${access_token}` } }
      );

      /** @type {Object} */
      const userInfo = userInfoResponse.data;

      // 🔄 Find or create Strapi admin user
      /** @type {Object} */
      const adminUser = await strapi
        .service('plugin::strapi-keycloak-passport.adminUserService')
        .findOrCreate(userInfo);

      // 🔥 Generate Strapi JWT
      /** @type {string} */
      const jwt = await strapi.admin.services.token.createJwtToken(adminUser);

      /** @type {{ id: string, firstname: string, lastname: string, username?: string, email: string }} */
      const minimalUserInfos = {
        id: adminUser.id,
        firstname: adminUser.firstname,
        lastname: adminUser.lastname,
        username: adminUser.username || null,
        email: adminUser.email,
      };

      // ✅ Store authenticated user in `ctx.state.user`
      ctx.session = {
        ...ctx.session,
        user: minimalUserInfos
      };

      return ctx.send({
        data: {
          token: jwt,
          user: {
            ...minimalUserInfos,
            isActive: adminUser.isActive,
            blocked: adminUser.blocked || false,
            createdAt: adminUser.createdAt,
            updatedAt: adminUser.updatedAt,
          },
        },
      });
    } catch (error) {
      strapi.log.error(
        `🔴 Authentication Failed for ${ctx.request.body?.email || 'unknown user'}:`,
        error.response?.data || error.message
      );

      return ctx.badRequest('Invalid credentials', {
        error: {
          status: error?.status ?? 400,
          name: error?.name ?? 'ApplicationError',
          message: error?.message ?? 'Invalid credentials',
          details: error?.details ?? {},
        },
      });
    }
  },
};