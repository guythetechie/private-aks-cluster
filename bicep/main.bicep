targetScope = 'subscription'

import { getPrefix, getAlphanumericPrefix } from 'functions.bicep'

param applicationName string
param tags object = {}
param location string
param allowedIpAddresses string?
@secure()
param virtualMachineAdminPassword string = '${newGuid()}2@'

func indexOfKey(map object, key string) int => indexOf(objectKeys(map), key)

var firewallName = '${getPrefix(applicationName, resourceGroup.id)}-firewall'
var aksClusterName = '${getPrefix(applicationName, resourceGroup.id)}-aks'
var privateDnsZones = {
  monitor: {
    name: 'privatelink.monitor.azure.com'
    isAmpls: true
  }
  oms: {
    name: 'privatelink.oms.opinsights.azure.com'
    isAmpls: true
  }
  ods: {
    name: 'privatelink.ods.opinsights.azure.com'
    isAmpls: true
  }
  agentsvc: {
    name: 'privatelink.agentsvc.azure-automation.net'
    isAmpls: true
  }
  blob: {
    name: 'privatelink.blob.${environment().suffixes.storage}'
    isAmpls: false
  }
  aks: {
    name: '${getPrefix(applicationName, resourceGroup.id)}.contoso.com'
    isAmpls: false
  }
  keyVault: {
    name: 'privatelink.${environment().suffixes.keyvaultDns}'
    isAmpls: false
  }
}

var subnets = {
  privateLink: {
    name: 'private-link'
    addressPrefix: '10.0.0.0/27'
    routeThroughFirewall: true
  }
  aksApi: {
    name: 'aks-api'
    addressPrefix: '10.0.0.32/28'
    routeThroughFirewall: true
    delegation: 'Microsoft.ContainerService/managedClusters'
  }
  virtualMachine: {
    name: 'virtual-machine'
    addressPrefix: '10.0.0.48/29'
    routeThroughFirewall: true
  }
  aksNode: {
    name: 'aks-node'
    addressPrefix: '10.0.0.64/26'
    routeThroughFirewall: true
  }
  firewall: {
    name: 'AzureFirewallSubnet'
    addressPrefix: '10.0.0.128/26'
    routeThroughFirewall: false
  }
  bastion: {
    name: 'AzureBastionSubnet'
    addressPrefix: '10.0.0.128/26'
    routeThroughFirewall: false
  }
}

var app1AksNamespaceName = 'app1'
var app1ServiceAccountName = 'app1'

var bastionName = '${getPrefix(applicationName, resourceGroup.id)}-bastion'

var keyVaultStorageAccountConnectionStringSecretName = 'storage-account-connection-string'

resource resourceGroup 'Microsoft.Resources/resourceGroups@2021-04-01' = {
  name: toLower('${applicationName}-rg')
  location: location
  tags: tags
}

module logAnalyticsWorkspace 'br/public:avm/res/operational-insights/workspace:0.11.0' = {
  scope: resourceGroup
  name: 'log-analytics-workspace'
  params: {
    name: '${getPrefix(applicationName, resourceGroup.id)}-log-analytics-workspace'
    tags: tags
    skuName: 'PerGB2018'
    dataRetention: 30
  }
}

module ampls 'br/public:avm/res/insights/private-link-scope:0.7.0' = {
  scope: resourceGroup
  name: 'ampls'
  params: {
    name: 'ampls'
    tags: tags
    accessModeSettings: {
      ingestionAccessMode: 'Open'
      queryAccessMode: 'Open'
    }
    scopedResources: [
      {
        name: logAnalyticsWorkspace.outputs.name
        linkedResourceId: logAnalyticsWorkspace.outputs.resourceId
      }
      {
        name: linuxDataCollectionEndpoint.outputs.name
        linkedResourceId: linuxDataCollectionEndpoint.outputs.resourceId
      }
    ]
  }
}

module amplsPrivateEndpoint 'br/public:avm/res/network/private-endpoint:0.10.1' = {
  scope: resourceGroup
  name: 'ampls-private-endpoint'
  params: {
    name: '${ampls.outputs.name}-azuremonitor-private-endpoint'
    location: location
    tags: tags
    subnetResourceId: privateLinkSubnet.id
    customNetworkInterfaceName: '${ampls.outputs.name}-azuremonitor-nic'
    privateLinkServiceConnections: [
      {
        name: 'azuremonitor'
        properties: {
          privateLinkServiceId: ampls.outputs.resourceId
          groupIds: [
            'azuremonitor'
          ]
        }
      }
    ]
    privateDnsZoneGroup: {
      name: 'private-dns-zone-group'
      privateDnsZoneGroupConfigs: [
        for index in map(
          filter(items(privateDnsZones), zone => zone.value.isAmpls),
          zone => indexOfKey(privateDnsZones, zone.key)
        ): {
          name: privateDnsZonesDeployment[index].outputs.name
          privateDnsZoneResourceId: privateDnsZonesDeployment[index].outputs.resourceId
        }
      ]
    }
  }
}

module privateDnsZonesDeployment 'br/public:avm/res/network/private-dns-zone:0.7.0' = [
  for zone in items(privateDnsZones): {
    scope: resourceGroup
    name: zone.value.name
    params: {
      name: zone.value.name
      tags: tags
      virtualNetworkLinks: [
        {
          virtualNetworkResourceId: virtualNetwork.id
        }
      ]
    }
  }
]

resource aksPrivateDnsZone 'Microsoft.Network/privateDnsZones@2024-06-01' existing = {
  name: privateDnsZonesDeployment[indexOfKey(privateDnsZones, 'aks')].outputs.name
  scope: resourceGroup
}

resource privateDnsZoneContributorRoleDefinition 'Microsoft.Authorization/roleDefinitions@2018-01-01-preview' existing = {
  scope: subscription()
  name: 'b12aa53e-6015-4669-85d0-8515ebb3ae7f'
}

module privateDnsZoneContributorAksAppRoutingRoleAssignment 'br/public:avm/ptn/authorization/resource-role-assignment:0.1.2' = {
  scope: resourceGroup
  name: 'private-dns-zone-contributor-aks-app-routing-role-assignment'
  params: {
    name: guid(aks.outputs.ingressPrincipalId, aksPrivateDnsZone.id, privateDnsZoneContributorRoleDefinition.id)
    principalId: aks.outputs.ingressPrincipalId
    resourceId: aksPrivateDnsZone.id
    roleDefinitionId: privateDnsZoneContributorRoleDefinition.id
  }
}

module linuxDataCollectionEndpoint 'br/public:avm/res/insights/data-collection-endpoint:0.5.0' = {
  scope: resourceGroup
  name: 'linux-data-collection-endpoint'
  params: {
    name: 'linux-data-collection-endpoint'
    location: location
    tags: tags
    kind: 'Linux'
    publicNetworkAccess: 'Enabled'
  }
}

module aksDataCollectionRule 'br/public:avm/res/insights/data-collection-rule:0.5.0' = {
  scope: resourceGroup
  name: 'aks-data-collection-rule'
  params: {
    name: '${getPrefix(applicationName, resourceGroup.id)}-aks-data-collection-rule'
    dataCollectionRuleProperties: {
      kind: 'Linux'
      dataCollectionEndpointResourceId: linuxDataCollectionEndpoint.outputs.resourceId
      dataFlows: [
        {
          streams: [
            'Microsoft-ContainerInsights-Group-Default'
          ]
          destinations: [
            logAnalyticsWorkspace.outputs.name
          ]
        }
      ]
      dataSources: {
        extensions: [
          {
            name: 'ContainerInsightsExtension'
            streams: [
              'Microsoft-ContainerInsights-Group-Default'
            ]
            extensionSettings: {
              dataCollectionSettings: {
                interval: '1m'
                namespaceFilteringMode: 'Exclude'
                enableContainerLogV2: true
              }
            }
            extensionName: 'ContainerInsights'
          }
        ]
        syslog: []
      }
      destinations: {
        logAnalytics: [
          {
            workspaceResourceId: logAnalyticsWorkspace.outputs.resourceId
            name: logAnalyticsWorkspace.outputs.name
          }
        ]
      }
    }
  }
}

module routeTable 'br/public:avm/res/network/route-table:0.4.0' = {
  scope: resourceGroup
  name: 'route-table'
  params: {
    name: '${getPrefix(applicationName, resourceGroup.id)}-route-table'
    location: location
    tags: tags
  }
}

module routeTableInternetRoute 'route-table-route.bicep' = {
  scope: resourceGroup
  name: 'route-table-internet-route'
  params: {
    route: {
      name: 'internet'
      properties: {
        addressPrefix: '0.0.0.0/0'
        nextHopType: 'VirtualAppliance'
        nextHopIpAddress: firewall.outputs.privateIp
      }
    }
    routeTableName: routeTable.outputs.name
  }
}

resource networkContributorRoleDefinition 'Microsoft.Authorization/roleDefinitions@2022-05-01-preview' existing = {
  name: '4d97b98b-1d4f-4787-a291-c67834d212e7'
  scope: subscription()
}

module virtualNetworkDeployment 'br/public:avm/res/network/virtual-network:0.5.2' = {
  scope: resourceGroup
  name: 'virtual-network'
  params: {
    name: '${getPrefix(applicationName, resourceGroup.id)}-virtual-network'
    location: location
    tags: tags
    addressPrefixes: [
      '10.0.0.0/24'
    ]
    subnets: [
      for subnet in items(subnets): {
        name: subnet.value.name
        addressPrefix: subnet.value.addressPrefix
        routeTableResourceId: subnet.value.routeThroughFirewall ? routeTable.outputs.resourceId : null
        delegation: subnet.value.?delegation
      }
    ]
  }
}

module vnetFlowLogs 'vnet-flow-logs.bicep' = {
  name: 'vnet-flow-logs-deployment'
  scope: az.resourceGroup('NetworkWatcherRG')
  params: {
    location: location
    logAnalyticsWorkspaceId: logAnalyticsWorkspace.outputs.resourceId
    networkWatcherName: 'NetworkWatcher_${location}'
    storageAccountId: storageAccount.outputs.resourceId
    virtualNetworkId: virtualNetwork.id
  }
}

resource virtualNetwork 'Microsoft.Network/virtualNetworks@2024-05-01' existing = {
  name: virtualNetworkDeployment.outputs.name
  scope: resourceGroup
}

resource privateLinkSubnet 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' existing = {
  name: subnets.privateLink.name
  parent: virtualNetwork
}

resource aksApiSubnet 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' existing = {
  name: subnets.aksApi.name
  parent: virtualNetwork
}

resource virtualMachineSubnet 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' existing = {
  name: subnets.virtualMachine.name
  parent: virtualNetwork
}

module aksIdentityApiSubnetRoleAssignment 'br/public:avm/ptn/authorization/resource-role-assignment:0.1.2' = {
  scope: resourceGroup
  name: 'aks-api-subnet-role-assignment'
  params: {
    name: guid(aksIdentity.outputs.principalId, aksApiSubnet.id, networkContributorRoleDefinition.id)
    principalId: aksIdentity.outputs.principalId
    resourceId: aksApiSubnet.id
    roleDefinitionId: networkContributorRoleDefinition.id
  }
}

resource aksNodeSubnet 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' existing = {
  name: subnets.aksNode.name
  parent: virtualNetwork
}

module aksIdentityNodeSubnetRoleAssignment 'br/public:avm/ptn/authorization/resource-role-assignment:0.1.2' = {
  scope: resourceGroup
  name: 'aks-node-subnet-role-assignment'
  params: {
    name: guid(aksIdentity.outputs.principalId, aksNodeSubnet.id, networkContributorRoleDefinition.id)
    principalId: aksIdentity.outputs.principalId
    resourceId: aksNodeSubnet.id
    roleDefinitionId: networkContributorRoleDefinition.id
  }
}

module firewallPublicIp 'br/public:avm/res/network/public-ip-address:0.8.0' = {
  scope: resourceGroup
  name: 'firewall-public-ip'
  params: {
    name: '${firewallName}-public-ip'
    location: location
    tags: tags
    zones: [
      1
      2
      3
    ]
    skuName: 'Standard'
    publicIPAllocationMethod: 'Static'
  }
}

module firewall 'br/public:avm/res/network/azure-firewall:0.5.2' = {
  scope: resourceGroup
  name: 'firewall'
  params: {
    name: firewallName
    location: location
    tags: tags
    azureSkuTier: 'Basic'
    publicIPResourceID: firewallPublicIp.outputs.resourceId
    virtualNetworkResourceId: virtualNetwork.id
    diagnosticSettings: [
      {
        name: 'enable-all'
        workspaceResourceId: logAnalyticsWorkspace.outputs.resourceId
        logAnalyticsDestinationType: 'Dedicated'
        logCategoriesAndGroups: [
          {
            categoryGroup: 'allLogs'
            enabled: true
          }
        ]
      }
    ]
  }
}

module firewallPolicy 'br/public:avm/res/network/firewall-policy:0.2.0' = {
  scope: resourceGroup
  name: 'firewall-policy'
  params: {
    name: '${getPrefix(applicationName, resourceGroup.id)}-firewall-policy'
    location: location
    tags: tags
    ruleCollectionGroups: [
      {
        name: 'default-network-collection-rule'
        priority: 500
        ruleCollections: [
          {
            ruleCollectionType: 'FirewallPolicyFilterRuleCollection'
            action: {
              type: 'Allow'
            }
            name: 'allow-outbound'
            priority: 1250
            rules: [
              {
                ruleType: 'NetworkRule'
                name: 'allow-outbound'
                ipProtocols: [
                  'Any'
                ]
                sourceAddresses: [
                  '*'
                ]
                destinationAddresses: [
                  '*'
                ]
                destinationPorts: [
                  '*'
                ]
              }
            ]
          }
        ]
      }
    ]
  }
}

module aksIdentity 'br/public:avm/res/managed-identity/user-assigned-identity:0.4.0' = {
  scope: resourceGroup
  name: 'aks-identity'
  params: {
    name: '${aksClusterName}-identity'
    location: location
    tags: tags
  }
}

module aks 'aks.bicep' = {
  scope: resourceGroup
  name: 'aks'
  params: {
    name: '${getPrefix(applicationName, resourceGroup.id)}-aks'
    location: location
    tags: tags
    apiSubnetResourceId: aksApiSubnet.id
    identityResourceId: aksIdentity.outputs.resourceId
    logAnalyticsWorkspaceResourceId: logAnalyticsWorkspace.outputs.resourceId
    nodeSubnetResourceId: aksNodeSubnet.id
    privateDnsZoneResourceId: aksPrivateDnsZone.id
    dataCollectionRuleAssociations: [
      {
        name: 'configurationAccessEndpoint'
        dataCollectionEndpointId: linuxDataCollectionEndpoint.outputs.resourceId
      }
      {
        name: aksDataCollectionRule.outputs.name
        dataCollectionRuleId: aksDataCollectionRule.outputs.resourceId
      }
    ]
  }
}

module keyVault 'br/public:avm/res/key-vault/vault:0.6.1' = {
  scope: resourceGroup
  name: 'key-vault'
  params: {
    name: '${getPrefix(applicationName, resourceGroup.id)}-vault'
    location: location
    tags: tags
    enableRbacAuthorization: true
    sku: 'standard'
    networkAcls: {
      defaultAction: 'Deny'
      bypass: 'AzureServices'
      ipRules: [
        {
          value: allowedIpAddresses
        }
      ]
    }
    diagnosticSettings: [
      {
        name: 'enable-all'
        workspaceResourceId: logAnalyticsWorkspace.outputs.resourceId
        logCategoriesAndGroups: [
          {
            categoryGroup: 'allLogs'
            enabled: true
          }
        ]
      }
    ]
    secrets: [
      {
        name: keyVaultStorageAccountConnectionStringSecretName
        value: storageAccount.outputs.primaryBlobEndpoint
      }
    ]
  }
}

resource keyVaultPrivateDnsZone 'Microsoft.Network/privateDnsZones@2024-06-01' existing = {
  name: privateDnsZonesDeployment[indexOfKey(privateDnsZones, 'keyVault')].outputs.name
  scope: resourceGroup
}

module keyVaultPrivateEndpoint 'br/public:avm/res/network/private-endpoint:0.10.1' = {
  scope: resourceGroup
  name: 'key-vault-private-endpoint'
  params: {
    name: '${keyVault.outputs.name}-vault-private-endpoint'
    location: location
    tags: tags
    subnetResourceId: privateLinkSubnet.id
    customNetworkInterfaceName: '${ampls.outputs.name}-vault-nic'
    privateLinkServiceConnections: [
      {
        name: 'vault'
        properties: {
          privateLinkServiceId: ampls.outputs.resourceId
          groupIds: [
            'vault'
          ]
        }
      }
    ]
    privateDnsZoneGroup: {
      name: 'private-dns-zone-group'
      privateDnsZoneGroupConfigs: [
        {
          name: keyVaultPrivateDnsZone.name
          privateDnsZoneResourceId: keyVaultPrivateDnsZone.id
        }
      ]
    }
  }
}

module storageAccount 'br/public:avm/res/storage/storage-account:0.18.0' = {
  scope: resourceGroup
  name: 'storage-account'
  params: {
    name: '${getAlphanumericPrefix(applicationName, resourceGroup.id)}stor'
    location: location
    tags: tags
    skuName: 'Standard_LRS'
    kind: 'StorageV2'
    allowSharedKeyAccess: false
    allowBlobPublicAccess: false
    supportsHttpsTrafficOnly: true
    networkAcls: {
      bypass: 'AzureServices'
      defaultAction: 'Deny'
      ipRules: [
        {
          value: allowedIpAddresses
        }
      ]
    }
  }
}

module storageAccountBlobServicesDiagnosticSettings 'storage-account-blob-diagnostic-settings.bicep' = {
  scope: resourceGroup
  name: 'storage-account-blob-diagnostic-settings'
  params: {
    name: 'enable-all'
    logAnalyticsWorkspaceResourceId: logAnalyticsWorkspace.outputs.resourceId
    storageAccountName: storageAccount.outputs.name
  }
}

resource storageAccountBlobPrivateDnsZone 'Microsoft.Network/privateDnsZones@2024-06-01' existing = {
  name: privateDnsZonesDeployment[indexOfKey(privateDnsZones, 'blob')].outputs.name
  scope: resourceGroup
}

module storageAccountBlobPrivateEndpoint 'br/public:avm/res/network/private-endpoint:0.10.1' = {
  scope: resourceGroup
  name: 'storage-account-private-endpoint'
  params: {
    name: '${storageAccount.outputs.name}-blob-private-endpoint'
    location: location
    tags: tags
    subnetResourceId: privateLinkSubnet.id
    customNetworkInterfaceName: '${storageAccount.outputs.name}-blob-nic'
    privateLinkServiceConnections: [
      {
        name: 'blob'
        properties: {
          privateLinkServiceId: storageAccount.outputs.resourceId
          groupIds: [
            'blob'
          ]
        }
      }
    ]
    privateDnsZoneGroup: {
      name: 'private-dns-zone-group'
      privateDnsZoneGroupConfigs: [
        {
          name: storageAccountBlobPrivateDnsZone.name
          privateDnsZoneResourceId: storageAccountBlobPrivateDnsZone.id
        }
      ]
    }
  }
}

module app1ManagedIdentity 'br/public:avm/res/managed-identity/user-assigned-identity:0.4.0' = {
  scope: resourceGroup
  name: 'app1-managed-identity'
  params: {
    name: '${getPrefix(applicationName, resourceGroup.id)}-app1-identity'
    location: location
    tags: tags
    federatedIdentityCredentials: [
      {
        name: aks.outputs.name
        audiences: [
          'api://AzureADTokenExchange'
        ]
        issuer: aks.outputs.oidcIssuerProfileUrl
        subject: 'system:serviceaccount:${app1AksNamespaceName}:${app1ServiceAccountName}'
      }
    ]
  }
}

module bastionPublicIp 'br/public:avm/res/network/public-ip-address:0.8.0' = {
  scope: resourceGroup
  name: 'bastion-public-ip'
  params: {
    name: '${bastionName}-public-ip'
    location: location
    tags: tags
    zones: [
      1
      2
      3
    ]
    skuName: 'Standard'
    publicIPAllocationMethod: 'Static'
  }
}

module bastion 'br/public:avm/res/network/bastion-host:0.6.0' = {
  scope: resourceGroup
  name: 'bastion'
  params: {
    name: bastionName
    location: location
    tags: tags
    bastionSubnetPublicIpResourceId: bastionPublicIp.outputs.resourceId
    virtualNetworkResourceId: virtualNetwork.id
  }
}

module jumpVirtualMachine 'br/public:avm/res/compute/virtual-machine:0.12.0' = {
  scope: resourceGroup
  name: 'jump-virtual-machine'
  params: {
    name: 'jump'
    location: location
    tags: tags
    adminUsername: 'jumpvmadmin'
    adminPassword: virtualMachineAdminPassword
    bootDiagnostics: true
    imageReference: {
      publisher: 'MicrosoftWindowsServer'
      offer: 'WindowsServer'
      sku: '2022-datacenter-azure-edition-hotpatch'
      version: 'latest'
    }
    priority: 'Spot'
    nicConfigurations: [
      {
        ipConfigurations: [
          {
            name: 'default'
            subnetResourceId: virtualMachineSubnet.id
          }
        ]
        nicSuffix: '-nic'
      }
    ]
    osDisk: {
      managedDisk: {
        storageAccountType: 'StandardSSD_LRS'
      }
    }
    osType: 'Windows'
    vmSize: 'Standard_D2ads_v6'
    zone: 0
  }
}

output aksClusterName string = aks.outputs.name
output app1ManagedIdentityClientId string = app1ManagedIdentity.outputs.principalId
output app1AksNamespaceName string = app1AksNamespaceName
output app1ServiceAccountName string = app1ServiceAccountName
output dnsZoneName string = aksPrivateDnsZone.name
output keyVaultName string = keyVault.outputs.name
output keyVaultUrl string = keyVault.outputs.uri
output keyVaultStorageAccountConnectionStringSecretName string = keyVaultStorageAccountConnectionStringSecretName
output resourceGroupName string = resourceGroup.name
