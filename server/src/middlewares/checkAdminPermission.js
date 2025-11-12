/**
 * Middleware to enforce Strapi admin permissions dynamically.
 *
 * @module CheckAdminPermissionMiddleware
 * @param {string} requiredPermission - The required permission UID.
 * @returns {Function} Middleware function.
 */
const checkAdminPermission = (requiredPermission) => async (ctx, next) => {
  try {
    // ✅ Use Admin User Info from `ctx.state.user` (Strapi v5)
    const adminUser = ctx.session.user;

    // Ensure user is authenticated
    if (!adminUser) {
      return ctx.unauthorized('User is not authenticated.');
    }

    /** @type {number[]} */
    const [roleId] = adminUser.roles.map(role => role.id);

    // ✅ Fetch permissions via Strapi Admin Services (Strapi v5)
    const adminPermissions = await strapi.admin.services.permission.findMany({
      where: {
        role: roleId,
        action: requiredPermission
      }
    });

    if (adminPermissions.length === 0) {
      return ctx.forbidden(`Access denied. Missing permission: ${requiredPermission}`);
    }

    // Proceed if permission is valid
    await next();
  } catch (error) {
    strapi.log.error('🔴 Error checking admin permission:', error);
    return ctx.internalServerError('Failed to verify permissions.');
  }
};

export default checkAdminPermission;
