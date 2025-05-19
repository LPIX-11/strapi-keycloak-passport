'use strict';

import authController from './controllers/authOverrideController';

/**
 * @module StrapiKeycloakBootstrap
 * @description Bootstraps the Strapi Keycloak Passport Plugin and overrides admin authentication routes.
 * @async
 * @function
 * @param {Object} strapi - The Strapi instance.
 */
const bootstrap = async ({ strapi }) => {
  strapi.log.info('🚀 Strapi Keycloak Passport Plugin Bootstrapped');

  try {
    strapi.log.info('🔍 Registering Keycloak Plugin Permissions...');

    const actions = [
      {
        section: 'plugins',
        displayName: 'Access Keycloak Plugin',
        uid: 'access',
        pluginName: 'strapi-keycloak-passport',
      },
      {
        section: 'plugins',
        displayName: 'View Role Mappings',
        uid: 'view-role-mappings',
        pluginName: 'strapi-keycloak-passport',
      },
      {
        section: 'plugins',
        displayName: 'Manage Role Mappings',
        uid: 'manage-role-mappings',
        pluginName: 'strapi-keycloak-passport',
      },
    ];

    await strapi.admin.services.permission.actionProvider.registerMany(actions);
    strapi.log.info('✅ Keycloak Plugin permissions successfully registered.');
  } catch (error) {
    strapi.log.error('❌ Failed to register Keycloak Plugin permissions:', error);
  }

  // ✅ Ensure Default Role Mapping Exists
  await ensureDefaultRoleMapping(strapi);

  // ✅ Apply Middleware to Intercept `/admin/login` Before Strapi Handles It
  overrideAdminRoutes(strapi);

  strapi.log.info('🔒 Passport Keycloak Strategy Initialized');
};

/**
 * Overrides admin authentication routes to use Keycloak.
 *
 * @function overrideAdminRoutes
 * @param {Object} strapi - The Strapi instance.
 */
function overrideAdminRoutes(strapi) {
  try {
    strapi.log.info('🛠 Applying Keycloak Authentication Middleware...');

    strapi.server.use(async (ctx, next) => {
      /** @type {string} */
      const requestPath = ctx.request.path;
      /** @type {string} */
      const requestMethod = ctx.request.method;

      if (requestPath === '/admin/login' && requestMethod === 'POST') {
        await authController.login(ctx);
        return;
      } else if (
        (
          requestPath.includes('auth/reset-password') ||
          requestPath.includes('auth/forgot-password') ||
          requestPath.includes('auth/register-admin') ||
          requestPath.includes('auth/register')) &&
        requestMethod === 'GET'
      ) {
        return ctx.redirect('/');
      } else {
        await next();
      }
    });

    strapi.log.info(`
      
    ╔════════════════════════════════╗
    ║      🛡️ PASSPORT APPLIED 🛡️      ║
    ╚════════════════════════════════╝
    `);
    strapi.log.info('🚴 Admin login request rerouted to passport.');
    strapi.log.info('📒 Registration route blocked. 🚫');
    strapi.log.info('🕵️‍♂️ Reset password route blocked. 🚫');
  } catch (error) {
    strapi.log.error('❌ Failed to register Keycloak Middleware:', error);
  }
}

/**
 * Ensures a default role mapping (SUPER_ADMIN -> Role ID 1) is created in the database.
 *
 * @async
 * @function ensureDefaultRoleMapping
 * @param {Object} strapi - The Strapi instance.
 */
async function ensureDefaultRoleMapping(strapi) {
  try {
    /** @type {Object} */
    const superAdminRole = await strapi.db
      .query('admin::role')
      .findOne({ where: { code: 'strapi-super-admin' } });

    if (!superAdminRole) {
      strapi.log.warn('⚠️ Super Admin role not found. Skipping default role mapping.');
      return;
    }

    /** @type {Object} */
    const DEFAULT_MAPPING = {
      keycloakRole: 'SUPER_ADMIN',
      strapiRole: superAdminRole.id, // 🔹 Fetch role ID dynamically
    };

    /** @type {Object} */
    const existingMapping = await strapi.db
      .query('plugin::strapi-keycloak-passport.role-mapping')
      .findOne({ where: { keycloakRole: DEFAULT_MAPPING.keycloakRole } });

    if (!existingMapping) {
      await strapi.db
        .query('plugin::strapi-keycloak-passport.role-mapping')
        .create({ data: DEFAULT_MAPPING });

      strapi.log.info(`✅ Default Role Mapping Created: ${DEFAULT_MAPPING.keycloakRole} -> ${DEFAULT_MAPPING.strapiRole} (mapped to Super Admin Role)`);
    } else {
      strapi.log.info(`✅ Default Role Mapping Already Exists: ${existingMapping.keycloakRole} -> ${existingMapping.strapiRole} (mapping to Super Admin Role)`);
    }
  } catch (error) {
    strapi.log.error('❌ Failed to create default role mapping:', error);
  }
}

export default bootstrap;