import axios from 'axios';

/**
 * @module AdminUserService
 * @description Handles Keycloak authentication and maps user roles in Strapi.
 * @param {Object} strapi - Strapi instance.
 * @returns {Object} - Service methods.
 */
const adminUserService = ({ strapi }) => ({
  /**
   * Finds or creates an admin user in Strapi and assigns the correct role.
   *
   * @async
   * @function findOrCreate
   * @param {Object} userInfo - The user data from Keycloak.
   * @param {string} userInfo.email - User's email.
   * @param {string} [userInfo.preferred_username] - Preferred username.
   * @param {string} [userInfo.given_name] - First name.
   * @param {string} [userInfo.family_name] - Last name.
   * @param {string} userInfo.sub - Unique Keycloak user ID.
   * @returns {Promise<Object>} The created or updated Strapi admin user.
   */
  async findOrCreate(userInfo) {
    try {
      /** @type {string} */
      const email = userInfo.email;
      /** @type {string} */
      const username = userInfo.preferred_username || '';
      /** @type {string} */
      const firstname = userInfo.given_name || '';
      /** @type {string} */
      const lastname = userInfo.family_name || '';
      /** @type {string} */
      const keycloakUserId = userInfo.sub;

      /** @type {Object|null} */
      const [adminUser] = await strapi.entityService.findMany('admin::user', {
        filters: { email },
        populate: { roles: true },
        limit: 1,
      });

      /** @type {Object<string, number>} */
      const roleMappings = await strapi
        .service('plugin::strapi-keycloak-passport.roleMappingService')
        .getMappings();

      /** @type {number} */
      const DEFAULT_ROLE_ID = strapi
        .config
        .get('plugin::strapi-keycloak-passport')
        .roleConfigs
        .defaultRoleId;

      /** @type {Set<number>} */
      let appliedRoles = new Set();

      try {
        // 🔥 Fetch user roles from Keycloak
        const keycloakRoles = await fetchKeycloakUserRoles(keycloakUserId, strapi);
        // 🔄 Map Keycloak roles to Strapi roles
        keycloakRoles.forEach((role) => {
          const mappedRole = roleMappings.find(mapped => mapped.keycloakRole === role);
          if (mappedRole) appliedRoles.add(mappedRole.strapiRole);
        });

      } catch (error) {
        strapi.log.error('❌ Failed to fetch user roles from Keycloak:', error.response?.data || error.message);
      }

      /** @type {number[]} */
      const userRoles = appliedRoles.size ? Array.from(appliedRoles) : [DEFAULT_ROLE_ID];

      // ✅ Efficiently create or update user only when needed
      if (!adminUser) {
        await strapi.entityService.create('admin::user', {
          data: {
            email,
            firstname,
            lastname,
            username,
            isActive: true,
            roles: userRoles,
          },
        });
      }

      if (JSON.stringify(adminUser?.roles) !== JSON.stringify(userRoles)) {
        await strapi.documents('admin::user').update({
          documentId: adminUser.documentId,
          data: {
            firstname,
            lastname,
            roles: userRoles,
          },
        });
      }

      return adminUser;
    } catch (error) {
      strapi.log.error('❌ Failed to create/update user:', error.message);
      throw new Error('Failed to create/update user.');
    }
  },
});

/**
 * Fetches user roles from Keycloak.
 *
 * @async
 * @function fetchKeycloakUserRoles
 * @param {string} keycloakUserId - The Keycloak user ID.
 * @param {Object} strapi - Strapi instance.
 * @returns {Promise<string[]>} Array of Keycloak role names.
 * @throws {Error} If request fails or user ID is invalid.
 */
async function fetchKeycloakUserRoles(keycloakUserId, strapi) {
  if (!keycloakUserId) throw new Error('❌ Keycloak user ID is missing!');

  const config = strapi.config.get('plugin::strapi-keycloak-passport');

  try {
    // 🔑 Fetch Keycloak Admin Token from service
    const accessToken = await strapi
      .plugin('strapi-keycloak-passport')
      .service('keycloakService')
      .fetchAdminToken();

    // 🔍 Fetch User Roles
    const rolesResponse = await axios.get(
      `${config.KEYCLOAK_AUTH_URL}/auth/admin/realms/${config.KEYCLOAK_REALM}/users/${keycloakUserId}/role-mappings/realm`,
      { headers: { Authorization: `Bearer ${accessToken}` } }
    );

    return rolesResponse.data.map(role => role.name);
  } catch (error) {
    strapi.log.error('❌ Failed to fetch Keycloak user roles:', error.response?.data || error.message);
    throw new Error('Failed to fetch Keycloak user roles.');
  }
}

export default adminUserService;
