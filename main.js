'use strict'

require('dotenv').config()

const express = require('express')

// Import middleware
const am = require('./middleware/auth_middleware')
const tm = require('./middleware/tenant_middleware')

// Import routes
const proxyRoutes = require('./routes/proxy_routes')

const app = express()
const PORT = process.env.PORT || 3000

// Parse JSON request bodies
app.use(express.json())

// Connect routes
proxyRoutes.connect(app, tm.tenantMiddleware, am.authMiddleware)

// Start server
app.listen(PORT, () => {
  console.log(`AI proxy server listening on port ${PORT}`)
  console.log(`Proxy endpoint: http://localhost:${PORT}/:tenantId/*`)
})
