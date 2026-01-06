# Multi-Tenant Proxy with JWT Authorization

A basic multi-tenant proxy server with JWT-based authorization, inspired by the secured-fhir-proxy pattern.

## Overview

This project demonstrates a multi-tenant proxy architecture where:
- Each tenant has its own configuration (backend URL, OAuth issuer, supported scopes)
- Requests are authenticated using JWT bearer tokens
- Tokens are validated against the tenant's configured JWKS endpoint
- Authorized requests are proxied to the tenant's backend service

## Project Structure

```
├── main.js                    # Express server entry point
├── tenants.json               # Tenant configurations
├── lib/
│   ├── tenant_config.js       # Tenant configuration loader
│   └── jwt_authorizer.js      # JWT validation and authorization
├── middleware/
│   └── auth_middleware.js     # Express middleware for auth
└── routes/
    ├── info_routes.js         # Health check and tenant info endpoints
    └── proxy_routes.js        # Proxy route handlers
```

## Installation

```bash
npm install
```

## Configuration

### Tenant Configuration

Edit `tenants.json` to configure your tenants:

```json
[
  {
    "id": "tenant-a",
    "name": "Tenant A",
    "backend_url": "https://api.example.com",
    "issuer": "https://your-okta-domain.okta.com/oauth2/default",
    "keys_endpoint": "https://your-okta-domain.okta.com/oauth2/default/v1/keys",
    "scopes_supported": ["openid", "profile", "api:read", "api:write"]
  }
]
```

### Environment Variables

- `PORT` - Server port (default: 3000)
- `API_BASE_URL` - Base URL for audience validation (optional)
- `CONFIG_PATH` - Path to configuration files (optional)

## Running the Server

```bash
# Production
npm start

# Development (with auto-reload)
npm run dev
```

## API Endpoints

### Public Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Health check |
| `GET /tenants` | List all tenants (public info only) |
| `GET /:tenantId/info` | Get specific tenant info |

### Protected Endpoints (require JWT)

| Endpoint | Description |
|----------|-------------|
| `* /:tenantId/proxy/*` | Proxy requests to tenant's backend |

## Usage Examples

### Check Health

```bash
curl http://localhost:3000/health
```

### List Tenants

```bash
curl http://localhost:3000/tenants
```

### Make Authenticated Proxy Request

```bash
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
     http://localhost:3000/tenant-a/proxy/users/1
```

## JWT Requirements

Access tokens must:
1. Be issued by the tenant's configured `issuer`
2. Be signed with a key available at the tenant's `keys_endpoint`
3. Contain appropriate scopes (`api:read` for GET, `api:write` for POST/PUT/DELETE)
4. Not be expired

## Scope Validation

The proxy validates scopes based on HTTP method:
- `GET`, `HEAD`, `OPTIONS` - Requires a scope containing "read" or `api:read`
- `POST`, `PUT`, `PATCH`, `DELETE` - Requires a scope containing "write" or `api:write`

## Extending the Proxy

### Adding Custom Authorization Logic

Modify `lib/jwt_authorizer.js` to add custom authorization rules.

### Adding New Routes

Create a new file in `routes/` and connect it in `main.js`.

### Adding Fine-Grained Access Control

Extend `middleware/auth_middleware.js` to add resource-level authorization.

## License

MIT
This is an example implementation of the Okta AI token vault. The example serves as a proxy that decorates AI agent requests with the proper credentials for making API calls.

Goals:
Enterprise environments today have many disparate solutions in place, on both the AI agent side of the equation, as well as the corporate resource side of the equation. In order to make it easy to keep pace with ever changing requirements from a security and interoperability standpoint, we need a centralizezd component that can implement all of the relevant standard functionality, and offer up those implementations as a centralized service for consumers and resources to take advantage of.

The goal of this solution is to create a standalone implementation of the Okta AI agent token vault service in a manner that can be easily plugged into any landscape. It will ensure that AI agents are able to access a wide variety of internal and external resources in a secure way, while not requiring the agent to directly obtain and manage security tokens for each resource. 

Functionality:
This proxy will allow the owner to configure multiple resources that this solution will proxy to. Each resource will be configured with an API audience it will use to protect itself, a backend URL, and token vault configuration. Upon request, if the call is allowed to be made (i.e. if it passes initial authorization checks, then it will use the auth0 configuration to attempt to retrieve backend credentials from the vault. If the user has consented already, then this works, otherwise this solution will work with the auth0 connected accounts flow to get the account connected and credential vaulted).