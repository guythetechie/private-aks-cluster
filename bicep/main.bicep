targetScope = 'subscription'

var location = 'eastus2'
var prefix = 'private-cluster'
var shortPrefix = 'pc'
var shortAlphanumericPrefix = 'pc'
var tags = {}

resource resourceGroup 'Microsoft.Resources/resourceGroups@2021-04-01' = {
  name: '${prefix}-rg'
  location: location
  tags: tags
}

module resources 'resources.bicep' = {
  scope: resourceGroup
  name: 'resources-deployment'
  params: {
    prefix: '${prefix}-${take(uniqueString(resourceGroup.id), 4)}'
    shortPrefix: '${shortPrefix}-${take(uniqueString(resourceGroup.id), 4)}'
    shortAlphanumericPrefix: '${shortAlphanumericPrefix}${take(uniqueString(resourceGroup.id), 4)}'
  }
}
