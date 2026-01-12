'use strict'

require('dotenv').config()

const express = require('express')

// Import middleware
const am = require('./middleware/auth_middleware')
const tm = require('./middleware/tenant_middleware')

// Import routes
const proxyRoutes = require('./routes/proxy_routes')
const oidcCallback = require('./routes/oidc_callback')
const protectedResourceMetadata = require('./routes/protected_resource_metadata')
const authorizationServerMetadata = require('./routes/authorization_server_metadata')
const dynamicClientRegistration = require('./routes/dynamic_client_registration')
const authorize = require('./routes/authorize')
const token = require('./routes/token')
const connectedAccountCallback = require('./routes/connected_accounts_callback')

const app = express()
const PORT = process.env.PORT || 3000

// Parse JSON request bodies
app.use(express.json())

// Parse URL-encoded request bodies (for OAuth token endpoint)
app.use(express.urlencoded({ extended: true }))

// Log all incoming requests
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`)
  next()
})

// Connect routes
// Protected resource metadata is a public endpoint (RFC 9728)
protectedResourceMetadata.connect(app)

// Authorization server metadata is a public endpoint (RFC 8414)
authorizationServerMetadata.connect(app)

// Dynamic client registration is a public endpoint (RFC 7591)
dynamicClientRegistration.connect(app)

// Authorize endpoint proxy redirects to real authorization server
authorize.connect(app)

// Token endpoint for exchanging authorization codes for tokens
token.connect(app)

// OIDC Callback
oidcCallback.connect(app)

//Connected Accounts Callback
connectedAccountCallback.connect(app)

//Regular route for actually doing stuff.
proxyRoutes.connect(app, tm.tenantMiddleware, am.authMiddleware)

// Start server
app.listen(PORT, () => {
  console.log(`AI proxy server listening on port ${PORT}`)
  console.log(`Proxy endpoint: http://localhost:${PORT}/:tenantId/*`)
})
