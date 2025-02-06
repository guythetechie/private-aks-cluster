targetScope = 'subscription'

param allowedIpAddresses string?
@secure()
param virtualMachineAdminPassword string = '${newGuid()}2@'

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
    allowedIpAddresses: map(split(allowedIpAddresses ?? '', ','), address => trim(address))
    shortPrefix: '${shortPrefix}-${take(uniqueString(resourceGroup.id), 4)}'
    shortAlphanumericPrefix: '${shortAlphanumericPrefix}${take(uniqueString(resourceGroup.id), 4)}'
    tags: tags
    virtualMachineAdminPassword: virtualMachineAdminPassword
  }
}

output aksClusterName string = resources.outputs.aksClusterName
output app1ManagedIdentityClientId string = resources.outputs.app1ManagedIdentityClientId
output app1AksNamespaceName string = resources.outputs.app1AksNamespaceName
output app1ServiceAccountName string = resources.outputs.app1ServiceAccountName
output dnsZoneName string = resources.outputs.dnsZoneName
output keyVaultName string = resources.outputs.keyVaultName
output keyVaultUrl string = resources.outputs.keyVaultUrl
output keyVaultStorageAccountConnectionStringSecretName string = resources.outputs.keyVaultStorageAccountConnectionStringSecretName
output resourceGroupName string = resourceGroup.name
