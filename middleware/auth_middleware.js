'use strict'

const jwtAuthorizer = require('../lib/jwt_authorizer')
/**
 * Middleware to validate JWT authorization.
 * Must be used after the tenant middleware.
 */
module.exports.authMiddleware = async function(req, res, next) {
  const tenantConfig = req.tenantConfig

  if (!tenantConfig) {
    return res.status(500).json({
      error: 'Internal Server Error',
      message: 'Tenant configuration not available. Ensure tenant middleware runs first.'
    })
  }

  const authResult = await jwtAuthorizer.authorizeRequest(
    tenantConfig,
    req.headers
  )
  console.log("Auth result")
  console.log(authResult)
  if (!authResult.success) {
    const resourceMetadataUrl = `${process.env.PROXY_BASE_URL}/.well-known/oauth-protected-resource/${req.tenantConfig.id}/${req.params[0]}`
    const wwwAuthValue = `Bearer error="invalid_or_misssing_jwt", error_description="${authResult.message}", resource_metadata="${resourceMetadataUrl}"`
    
    res.set('WWW-Authenticate', wwwAuthValue)
    return res.status(authResult.statusCode).json({
      error: authResult.statusCode === 401 ? 'Unauthorized' : 'Forbidden',

      message: authResult.message
    })
  }

  // Attach authorization context to request for use in handlers
  req.authContext = {
    accessToken: authResult.token
  }
  
  console.log(req.authContext)
  next()
}
