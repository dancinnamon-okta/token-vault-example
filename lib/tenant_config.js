'use strict'

const fs = require('fs')
const path = require('path')

/**
 * Retrieves tenant configuration by tenant ID.
 * @param {string} tenantId - The unique identifier for the tenant
 * @returns {object} - The tenant configuration or an empty object if not found
 */
module.exports.getTenantConfig = (tenantId) => {
  const configPath = process.env.CONFIG_PATH || __dirname + '/..' //Take from environment variable, or use root of project.

  try {
    const configData = JSON.parse(fs.readFileSync(path.resolve(configPath, 'tenants.json')))
    const foundConfig = configData.filter(config => config.id === tenantId)
    
    if (foundConfig.length > 0) {
      return foundConfig[0]
    }
    
    return null
  } catch (error) {
    console.error('Error loading tenant configuration:', error.message)
    return null
  }
}