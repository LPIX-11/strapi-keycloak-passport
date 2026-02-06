# Strapi Keycloak Passport Plugin

Enterprise-grade Keycloak authentication for Strapi v5 Admin Panel with full RBAC support.

[![npm version](https://img.shields.io/npm/v/strapi-keycloak-passport.svg)](https://www.npmjs.com/package/strapi-keycloak-passport)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Strapi v5](https://img.shields.io/badge/Strapi-v5-blue.svg)](https://strapi.io/)

## Features

- **Single Sign-On (SSO)** - Replace Strapi's default admin login with Keycloak OAuth2
- **Keycloak 17+ Support** - Works with both modern (17+) and legacy Keycloak versions
- **Role Mapping** - Dynamically map Keycloak roles to Strapi admin roles via UI
- **Token Caching** - Intelligent caching with automatic refresh before expiry
- **Audit Logging** - Comprehensive audit trail for all authentication events
- **Strapi RBAC Integration** - Leverages Strapi's native Roles & Permissions
- **Secure by Default** - Error sanitization, HttpOnly cookies, input validation

## Requirements

- Node.js >= 20.0.0
- Strapi v5.x
- Keycloak 17+ (or legacy with configuration flag)

## Installation

```bash
yarn add strapi-keycloak-passport
```

or

```bash
npm install strapi-keycloak-passport
```

## Configuration

### Plugin Configuration

Add to your `config/plugins.js` (or `config/plugins.ts`):

```javascript
module.exports = ({ env }) => ({
  'strapi-keycloak-passport': {
    enabled: env.bool('KEYCLOAK_ENABLED', true),
    config: {
      // Required: Keycloak server URL (without trailing slash)
      KEYCLOAK_AUTH_URL: env('KEYCLOAK_AUTH_URL', 'https://keycloak.example.com'),

      // Required: Keycloak realm name
      KEYCLOAK_REALM: env('KEYCLOAK_REALM', 'master'),

      // Required: OAuth client credentials
      KEYCLOAK_CLIENT_ID: env('KEYCLOAK_CLIENT_ID', 'strapi-admin'),
      KEYCLOAK_CLIENT_SECRET: env('KEYCLOAK_CLIENT_SECRET'),

      // Optional: Set to true for Keycloak versions < 17 (uses /auth prefix)
      KEYCLOAK_LEGACY_MODE: env.bool('KEYCLOAK_LEGACY_MODE', false),

      // Optional: Role configuration
      roleConfigs: {
        // Default Strapi role ID when no mapping exists
        defaultRoleId: env.int('KEYCLOAK_DEFAULT_ROLE_ID', 1),

        // Keycloak roles to exclude from the mapping UI
        excludedRoles: [
          'uma_authorization',
          'offline_access',
          'default-roles-master',
        ],
      },
    },
  },
});
```

### Environment Variables

```bash
# Required
KEYCLOAK_AUTH_URL=https://keycloak.example.com
KEYCLOAK_REALM=master
KEYCLOAK_CLIENT_ID=strapi-admin
KEYCLOAK_CLIENT_SECRET=your-client-secret

# Optional
KEYCLOAK_ENABLED=true
KEYCLOAK_LEGACY_MODE=false
KEYCLOAK_DEFAULT_ROLE_ID=1
```

### Keycloak Version Compatibility

| Keycloak Version | `KEYCLOAK_LEGACY_MODE` | URL Format |
|------------------|------------------------|------------|
| 17+ (Quarkus) | `false` (default) | `https://keycloak.example.com/realms/{realm}/...` |
| < 17 (WildFly) | `true` | `https://keycloak.example.com/auth/realms/{realm}/...` |

## Keycloak Setup

### 1. Create an OAuth Client

1. Navigate to **Keycloak Admin Console** → **Clients**
2. Click **Create Client**:
   - **Client ID**: `strapi-admin`
   - **Client Protocol**: `openid-connect`
   - **Client Authentication**: `On` (Confidential)
3. Configure settings:
   - **Root URL**: `https://your-strapi-instance.com`
   - **Valid Redirect URIs**: `https://your-strapi-instance.com/admin/*`
   - **Web Origins**: `https://your-strapi-instance.com`
4. Go to **Credentials** tab and copy the **Client Secret**

### 2. Assign Required Roles to Client

For the plugin to fetch user roles, the client needs realm-management permissions:

1. Go to **Clients** → `strapi-admin` → **Service Account Roles**
2. Click **Assign role**
3. Filter by **realm-management** client
4. Assign these roles:
   - `view-users`
   - `view-realm`
   - `manage-users` (optional, for future features)

### 3. Create Keycloak Roles

1. Go to **Realm Roles** → **Create Role**
2. Create roles that will map to Strapi admin roles:
   - `STRAPI_SUPER_ADMIN`
   - `STRAPI_EDITOR`
   - `STRAPI_AUTHOR`

### 4. Assign Roles to Users

1. Go to **Users** → Select a user → **Role Mapping**
2. Assign the appropriate Keycloak role

## Role Mapping

### Managing Mappings via Admin UI

1. Log in to Strapi Admin Panel
2. Navigate to **Settings** → **Keycloak Passport**
3. Map Keycloak roles to Strapi admin roles
4. Click **Save**

### Example Mapping

| Keycloak Role | Strapi Role |
|---------------|-------------|
| `STRAPI_SUPER_ADMIN` | Super Admin (1) |
| `STRAPI_EDITOR` | Editor (2) |
| `STRAPI_AUTHOR` | Author (3) |

### How It Works

1. User logs in with Keycloak credentials
2. Plugin fetches user's Keycloak roles
3. Roles are mapped to Strapi roles using saved mappings
4. If no mapping exists, user gets the `defaultRoleId` role
5. User is created/updated in Strapi with assigned roles

## Authentication Flow

```
┌─────────────┐                    ┌─────────────┐                    ┌─────────────┐
│    User     │                    │   Strapi    │                    │  Keycloak   │
└──────┬──────┘                    └──────┬──────┘                    └──────┬──────┘
       │                                  │                                  │
       │  1. POST /admin/login            │                                  │
       │  (email + password)              │                                  │
       │─────────────────────────────────>│                                  │
       │                                  │                                  │
       │                                  │  2. OAuth2 Password Grant        │
       │                                  │─────────────────────────────────>│
       │                                  │                                  │
       │                                  │  3. Access Token                 │
       │                                  │<─────────────────────────────────│
       │                                  │                                  │
       │                                  │  4. GET /userinfo                │
       │                                  │─────────────────────────────────>│
       │                                  │                                  │
       │                                  │  5. User Info + Roles            │
       │                                  │<─────────────────────────────────│
       │                                  │                                  │
       │                                  │  6. Find/Create Admin User       │
       │                                  │  7. Map Roles                    │
       │                                  │  8. Generate Strapi JWT          │
       │                                  │                                  │
       │  9. JWT Token + User             │                                  │
       │<─────────────────────────────────│                                  │
       │                                  │                                  │
```

## API Endpoints

All endpoints are prefixed with `/strapi-keycloak-passport/`

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| `POST` | `/admin/login` | Authenticate via Keycloak | No |
| `GET` | `/keycloak-roles` | Fetch available Keycloak & Strapi roles | Yes |
| `GET` | `/get-keycloak-role-mappings` | Get saved role mappings | Yes |
| `POST` | `/save-keycloak-role-mappings` | Save role mappings | Yes |
| `GET` | `/test-connection` | Test Keycloak connectivity | Yes |
| `GET` | `/token-cache-stats` | Get token cache statistics | Yes |
| `POST` | `/invalidate-token` | Invalidate cached admin token | Yes |

## Features in Detail

### Token Caching

Admin tokens are cached in-memory with automatic refresh:

- Tokens are cached using a composite key: `serverUrl:realm:clientId`
- Automatic refresh triggered 60 seconds before expiry
- Cache is invalidated when configuration changes
- Monitor cache via `/token-cache-stats` endpoint

### Audit Logging

All authentication events are logged to the database:

| Event | Logged Data |
|-------|-------------|
| Login Success | User email, Keycloak ID, assigned roles, IP, user agent |
| Login Failure | Attempted email, failure reason, IP, user agent |
| User Created | Email, Strapi ID, Keycloak ID, assigned roles |
| User Updated | Email, changed fields (roles, name, etc.) |
| Role Mapping Changed | Keycloak role, Strapi role, performed by |

Query audit logs via Strapi's Content Manager or API.

### Error Handling

The plugin implements a sanitized error pattern:

- **Internal errors** are logged with full details for debugging
- **Client responses** contain safe, generic messages
- Sensitive information (tokens, secrets) never exposed in responses

## Security Considerations

- **Client Secret**: Store securely in environment variables, never commit
- **Token Storage**: Admin tokens cached in-memory only, never persisted
- **Cookies**: HttpOnly, Secure (in production), SameSite protection
- **Input Validation**: All inputs validated before processing
- **Audit Trail**: All authentication events logged for compliance

## Troubleshooting

### "Failed to authenticate with Keycloak"

1. Verify `KEYCLOAK_AUTH_URL` is correct (no trailing slash)
2. Check if `KEYCLOAK_LEGACY_MODE` matches your Keycloak version
3. Confirm client secret is correct
4. Ensure client has proper service account roles

### "Failed to fetch roles from Keycloak"

1. Verify the client has `view-users` and `view-realm` roles assigned
2. Check Keycloak server logs for permission errors

### "User gets wrong role"

1. Check role mappings in Admin Panel
2. Verify user has the expected role in Keycloak
3. Check if role is in `excludedRoles` configuration

### Test Connection

Use the built-in connection test:

```bash
curl -X GET "https://your-strapi.com/strapi-keycloak-passport/test-connection" \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN"
```

## Changelog

### v0.3.0

- Added Keycloak 17+ support with `KEYCLOAK_LEGACY_MODE` option
- Implemented token caching with automatic refresh
- Added comprehensive audit logging
- Refactored to centralized constants (no magic values)
- Implemented error sanitization pattern
- Added new endpoints: `/test-connection`, `/token-cache-stats`, `/invalidate-token`
- Full JSDoc documentation
- Simplified configuration (removed `KEYCLOAK_TOKEN_URL`, `KEYCLOAK_USERINFO_URL`)

### v0.2.x

- Initial release with basic Keycloak authentication
- Role mapping UI
- Strapi v5 compatibility

## Contributing

Contributions are welcome! Please read our contributing guidelines before submitting PRs.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Support

- [GitHub Issues](https://github.com/LPIX-11/strapi-keycloak-passport/issues)
- [Documentation](https://github.com/LPIX-11/strapi-keycloak-passport#readme)
