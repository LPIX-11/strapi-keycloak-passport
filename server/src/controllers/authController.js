'use strict';

import axios from 'axios';

/**
 * @module AuthController
 * @description Handles Keycloak authentication and role management.
 */
export default {
  /**
   * Fetches all Keycloak roles and Strapi admin roles.
   *
   * @async
   * @function getRoles
   * @param {Object} ctx - Koa context.
   * @returns {Promise<Object>} - Object containing Keycloak roles and Strapi roles.
   * @throws {Error} If fetching roles fails.
   */
  async getRoles(ctx) {
    try {
      const config = strapi.config.get('plugin::strapi-keycloak-passport');

      // 🔑 Get Admin Token
      const accessToken = await strapi
        .plugin('strapi-keycloak-passport')
        .service('keycloakService')
        .fetchAdminToken();

      // 🔍 Fetch Keycloak Roles using Admin Token
      const rolesResponse = await axios.get(
        `${config.KEYCLOAK_AUTH_URL}/auth/admin/realms/${config.KEYCLOAK_REALM}/roles`,
        { headers: { Authorization: `Bearer ${accessToken}` } }
      );

      /** @type {Object[]} */
      const keycloakRoles = rolesResponse.data.filter(
        role => !config.roleConfigs.excludedRoles.includes(role.name)
      );

      /** @type {Object[]} */
      const strapiRoles = await strapi.entityService.findMany('admin::role', {});

      return ctx.send({ keycloakRoles, strapiRoles });
    } catch (error) {
      strapi.log.error(
        '❌ Failed to fetch Keycloak roles: Have you tried giving the role "MANAGE-REALM" and "MANAGE-USERS"?',
        error.response?.data || error.message
      );
      return ctx.badRequest('Failed to fetch Keycloak roles');
    }
  },

  /**
   * Retrieves Keycloak-to-Strapi role mappings.
   *
   * @async
   * @function getRoleMappings
   * @param {Object} ctx - Koa context.
   * @returns {Promise<Object>} - Object mapping Keycloak roles to Strapi roles.
   * @throws {Error} If retrieval fails.
   */
  async getRoleMappings(ctx) {
    try {
      const mappings = await strapi
        .service('plugin::strapi-keycloak-passport.roleMappingService')
        .getMappings();

      // Convert array of mappings into an object
      /** @type {Object} */
      const formattedMappings = mappings.reduce((acc, mapping) => {
        acc[mapping.keycloakRole] = mapping.strapiRole;
        return acc;
      }, {});

      return ctx.send(formattedMappings);
    } catch (error) {
      strapi.log.error('❌ Failed to retrieve role mappings:', error.response?.data || error.message);
      return ctx.badRequest('Failed to retrieve role mappings');
    }
  },

  /**
   * Saves Keycloak-to-Strapi role mappings.
   *
   * @async
   * @function saveRoleMappings
   * @param {Object} ctx - Koa context.
   * @param {Object} ctx.request - Request object.
   * @param {Object} ctx.request.body - Request body containing role mappings.
   * @param {Object<string, number>} ctx.request.body.mappings - Object mapping Keycloak roles to Strapi roles.
   * @returns {Promise<Object>} - Confirmation message.
   * @throws {Error} If saving fails.
   */
  async saveRoleMappings(ctx) {
    try {
      /** @type {Object<string, number>} */
      const { mappings } = ctx.request.body;

      await strapi.plugin('strapi-keycloak-passport')
        .service('roleMappingService')
        .saveMappings(mappings);

      return ctx.send({ message: 'Mappings saved successfully.' });
    } catch (error) {
      strapi.log.error('❌ Failed to save role mappings:', error.response?.data || error.message);
      return ctx.badRequest('Failed to save role mappings');
    }
  },
};
