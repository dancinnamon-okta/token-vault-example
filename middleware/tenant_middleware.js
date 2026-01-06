'use strict'

const TenantConfig = require('../lib/tenant_config')
/**
 * Middleware to extract and validate tenant from the request.
 * Must be used before the auth middleware.
 */
module.exports.tenantMiddleware = function(req, res, next) {
  const tenantId = req.params.tenantId

  if (!tenantId) {
    return res.status(400).json({
      error: 'Bad Request',
      message: 'Tenant ID is required in the URL path.'
    })
  }

  const tenantConfig = TenantConfig.getTenantConfig(tenantId)

  if (!tenantConfig) {
    return res.status(404).json({
      error: 'Not Found',
      message: `Tenant '${tenantId}' not found.`
    })
  }

  // Attach tenant config to request for use in subsequent middleware/handlers
  req.tenantConfig = tenantConfig
  next()
}