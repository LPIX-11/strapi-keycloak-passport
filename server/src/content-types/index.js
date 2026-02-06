/**
 * @fileoverview Content type exports for the Strapi Keycloak Passport plugin.
 * @module content-types
 * @author Strapi Keycloak Passport Team
 */

import roleMapping from './role-mapping';
import auditLog from './audit-log';

export default {
  'role-mapping': roleMapping,
  'audit-log': auditLog,
};
