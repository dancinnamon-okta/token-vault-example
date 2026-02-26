# MCP Authentication Proxy with Okta + Auth0 Token Vault

## WARNING: Early release not intended for production use!

## Overview

This proxy enables MCP (Model Context Protocol) clients like VS Code to securely connect to downstream MCP servers (GitHub, Atlassian, etc.) by presenting a **standard OIDC interface** while leveraging **Okta for access control** and **Auth0 Token Vault** for credential management.

**Note:** Currently this proxy will only represent 1 MCP client/agent.  Multiple downstream MCP servers may be configured.

### Key Capabilities

- **Standard OIDC Interface**: Exposes OAuth 2.0/OIDC endpoints (`/authorize`, `/token`, `/.well-known/*`) that MCP clients can use natively
- **Static DCR Endpoint**: Exposes a /register endpoint that can be invoked by MCP clients. This endpoint does not actually register any new clients, but instead will return statically pre-registered client information.
- **Okta Access Control**: Authenticates users via Okta OIDC and contains the actual Agentic Identity credentials. XAA is performed on the proxy with this agentic identity.
- **Auth0 Token Vault Integration**: Retrieves vaulted credentials for downstream MCP servers without exposing them to the client
- **Connected Accounts Flow**: If vaulted credentials are not available, the Auth0 connected accounts flow will be used to obtain those credentials.
- **Multi-Tenant Configuration**: Supports multiple downstream MCP servers (GitHub, Atlassian JIRA, etc.) with per-tenant configuration


### Architecture

```
┌─────────────────┐     OIDC      ┌──────────────────────┐     Okta      ┌─────────────┐
│   MCP Client    │◄────────────►│   MCP Auth Proxy     │◄────────────►│    Okta     │
│   (VS Code)     │              │                      │              │   (IdP)     │
└─────────────────┘              │  • OIDC Endpoints    │              └─────────────┘
                                 │  • Policy Enforcement│
                                 │  • Token Brokering   │              ┌─────────────┐
                                 │                      │◄────────────►│ Auth0 Token │
                                 └──────────┬───────────┘   Vault API  │   Vault     │
                                            │                          └─────────────┘
                                            │ MCP Protocol
                                            ▼
                                 ┌──────────────────────┐
                                 │  Downstream MCP      │
                                 │  Servers (GitHub,    │
                                 │  Atlassian, etc.)    │
                                 └──────────────────────┘
```

### High-Level Flow

1. **MCP Client initiates OIDC login**: The client (e.g., VS Code) discovers the proxy's OIDC endpoints and begins an authorization code flow with PKCE.
2. **User authenticates with Okta**: The proxy redirects to Okta for authentication and policy evaluation.
3. **Account linking (if needed)**: If the user hasn't linked their downstream account (e.g., GitHub), the proxy initiates the Auth0 Connected Accounts flow.
4. **Tokens issued to client**: The proxy issues tokens to the MCP client that can be used for subsequent requests.
5. **Proxied MCP requests**: When the client makes MCP requests, it does so using an access token minted by Okta. This token was obtained using XAA with agentic identity and policy. The proxy will then exchange the validated Okta token with vaulted credentials retreived from the Auth0 Token Vault and forwards the request to the downstream MCP server with proper authentication.

## Installation

```bash
npm install
```

## Configuration

### Tenant Configuration

Copy `tenants.example.json` to `tenants.json` and configure your downstream MCP servers:

```json
[
  {
    "id": "github",
    "name": "GitHub via MCP Auth Proxy",
    "backend_url": "https://api.githubcopilot.com",
    "issuer": "https://your-okta-domain.okta.com/oauth2/authz_server_id",
    "keys_endpoint": "https://your-okta-domain.okta.com/oauth2/authz_server_id/v1/keys",
    "vault_connection": "github",
    "external_scopes": ["refresh_token", "repo", "user", "read:org"]
  },
  {
    "id": "jira",
    "name": "JIRA via MCP Auth Proxy",
    "backend_url": "https://mcp.atlassian.com",
    "issuer": "https://your-okta-domain.okta.com/oauth2/authz_server_id",
    "keys_endpoint": "https://your-okta-domain.okta.com/oauth2/authz_server_id/v1/keys",
    "vault_connection": "jira",
    "external_scopes": ["refresh_token", "mcp"]
  }
]
```

| Field | Description |
|-------|-------------|
| `id` | Unique tenant identifier used in URL paths |
| `name` | Human-readable name for the tenant |
| `backend_url` | Downstream MCP server URL |
| `issuer` | Okta authorization server issuer URL that protects this MCP instance |
| `keys_endpoint` | Okta JWKS endpoint for token validation |
| `vault_connection` | Auth0 Token Vault connection name |
| `external_scopes` | OAuth scopes to request from the downstream provider. These must be configured in the agent's managed connection in Okta. |

### Environment Variables

Copy `.env.example` to `.env` and configure:

```bash
# Server Configuration
PROXY_BASE_URL=http://localhost:3000
PORT=3000

# Okta Configuration (Identity Provider)
OKTA_DOMAIN=https://your-okta-domain.okta.com

# Auth0 Token Vault Configuration
AUTH0_DOMAIN=your-auth0-domain.auth0.com
AUTH0_CTE_CLIENT_ID=your-cte-client-id
AUTH0_CTE_CLIENT_SECRET=your-cte-client-secret
AUTH0_VAULT_CLIENT_ID=your-vault-client-id
AUTH0_VAULT_CLIENT_SECRET=your-vault-client-secret
AUTH0_VAULT_AUDIENCE=https://token-vault-gateway
AUTH0_VAULT_SCOPE=api:full

# MCP Client Configuration (e.g., VS Code)
VSCODE_CLIENT=your-registered-vscode-client-id
VSCODE_SECRET=your-registered-vscode-client-secret

# Agent Configuration (for XAA/ID-JAG flows)
AGENT_CLIENT_ID=your-okta-agent-client-id
AGENT_PRIVATE_KEY_PATH=./agent_private_key.pem
AGENT_PRIVATE_KEY_ID=your-okta-agent-key-id
```

## Running the Server

```bash
# Production
npm start

# Development (with auto-reload)
npm run dev
```

## API Endpoints

### OIDC Discovery Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /.well-known/oauth-protected-resource/:tenantId` | RFC 9728 Protected Resource Metadata |
| `GET /.well-known/oauth-authorization-server` | RFC 8414 Authorization Server Metadata |
| `POST /register` | RFC 7591 Dynamic Client Registration |

### OAuth 2.0 Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /authorize/:tenantId` | Authorization endpoint - redirects to Okta |
| `POST /token` | Token endpoint - exchanges codes for tokens |
| `GET /callback` | OIDC callback from Okta |
| `GET /connected-accounts/callback` | Auth0 Connected Accounts callback |

### MCP Proxy Endpoints

| Endpoint | Description |
|----------|-------------|
| `* /:tenantId/*` | Proxies MCP requests to the tenant's backend server |

## Usage with VS Code

1. Configure VS Code to use this proxy as the MCP server endpoint
2. When VS Code initiates a connection, it will discover the OIDC endpoints
3. The user will be redirected to Okta for authentication
4. If needed, the user will complete the Connected Accounts flow to link their GitHub/Atlassian account
5. VS Code receives tokens and can make MCP requests through the proxy

### Example: Connecting to GitHub MCP

```
MCP Server URL: http://localhost:3000/github
```

The proxy will:
1. Present OIDC endpoints for VS Code to authenticate
2. Authenticate the user via Okta
3. Retrieve GitHub credentials from Auth0 Token Vault
4. Forward MCP requests to `https://api.githubcopilot.com` with proper GitHub authentication

## License

MIT