# Okta AI Token Vault Proxy (Multi-Tenant)

## WARNING: Early release not intended for production use!

## Overview

This project is a reference proxy that integrates with the Okta AI Token Vault to securely broker access from AI agents to protected APIs without exposing or managing downstream credentials in the agent. It provides:

- Multi-tenant/resource configuration: per-tenant issuer/JWKS, backend URL, and vault connection details
- Inbound authentication: validates the agent’s JWT (issuer + JWKS) and enforces scopes
- Outbound credential brokering: retrieves or acquires downstream API credentials via the Token Vault, then decorates the proxied request (for example, attaches a downstream access token)
- Least-privilege scope enforcement based on HTTP method (read/write)
- Simple proxying to the configured backend service for each tenant

High-level flow:
1. Client/agent sends a request with a bearer token to this proxy.
2. Proxy validates the token (issuer, signature via JWKS, expiration) and checks scopes.
3. Proxy looks up tenant/resource config and requests downstream credentials from the Token Vault (using the configured connection).
4. If consent/connection is required, the proxy surfaces an authorization error indicating the connected-accounts flow is needed.
5. On success, the proxy forwards the request to the backend service with the appropriate downstream Authorization header.

## Installation

```bash
npm install
```

## Configuration

### Tenant Configuration

Copy `tenants.example.json` to `tenants.json` configure your tenants.

### Environment Variables

Copy `.env.example` to `.env` to configure global settings.

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

```bash
curl http://localhost:3000/github/mcp
```
This example is found in tenants.example.json, and the proxy would forward to: https://api.githubcopilot.com/mcp

## License

MIT
This is an example implementation of the Okta AI token vault. The example serves as a proxy that decorates AI agent requests with the proper credentials for making API calls.

Goals:
Enterprise environments today have many disparate solutions in place, on both the AI agent side of the equation, as well as the corporate resource side of the equation. In order to make it easy to keep pace with ever changing requirements from a security and interoperability standpoint, we need a centralizezd component that can implement all of the relevant standard functionality, and offer up those implementations as a centralized service for consumers and resources to take advantage of.

The goal of this solution is to create a standalone implementation of the Okta AI agent token vault service in a manner that can be easily plugged into any landscape. It will ensure that AI agents are able to access a wide variety of internal and external resources in a secure way, while not requiring the agent to directly obtain and manage security tokens for each resource. 

Functionality:
This proxy will allow the owner to configure multiple resources that this solution will proxy to. Each resource will be configured with an API audience it will use to protect itself, a backend URL, and token vault configuration. Upon request, if the call is allowed to be made (i.e. if it passes initial authorization checks, then it will use the auth0 configuration to attempt to retrieve backend credentials from the vault. If the user has consented already, then this works, otherwise this solution will work with the auth0 connected accounts flow to get the account connected and credential vaulted).