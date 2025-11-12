import axios from 'axios';

/**
 * @module KeycloakService
 * @description Handles Keycloak authentication and provides utility functions.
 * @param {Object} strapi - Strapi instance.
 * @returns {Object} - Keycloak service methods.
 */
const keycloakService = ({ strapi }) => ({
  /**
   * Fetches an admin access token from Keycloak.
   *
   * @async
   * @function fetchAdminToken
   * @returns {Promise<string>} The Keycloak access token.
   * @throws {Error} If authentication fails.
   */
  async fetchAdminToken() {
    const config = strapi.config.get('plugin::strapi-keycloak-passport');

    try {
      // 🔥 Send request to Keycloak for an admin token
      const tokenResponse = await axios.post(
        `${config.KEYCLOAK_AUTH_URL}${config.KEYCLOAK_TOKEN_URL}`,
        new URLSearchParams({
          client_id: config.KEYCLOAK_CLIENT_ID,
          client_secret: config.KEYCLOAK_CLIENT_SECRET,
          scope: 'openid profile email',
          grant_type: 'client_credentials',
        }).toString(),
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
      );

      /** @type {string | undefined} */
      const accessToken = tokenResponse.data?.access_token;

      // 🔄 Ensure access token is valid
      if (!accessToken) {
        throw new Error('❌ Keycloak returned an empty access token');
      }

      strapi.log.info('✅ Successfully fetched Keycloak admin token.');
      return accessToken;
    } catch (error) {
      strapi.log.error('❌ Keycloak Admin Token Fetch Error:', {
        status: error.response?.status || 'Unknown',
        message: error.response?.data || error.message,
      });

      throw new Error('Failed to fetch Keycloak admin token');
    }
  },
});

export default keycloakService;
