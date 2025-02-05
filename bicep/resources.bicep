param location string = 'eastus2'
param prefix string
param shortPrefix string
param shortAlphanumericPrefix string
param tags object = {}
param allowedIpAddresses array = []

var privateLinkSubnetName = 'private-link'
var aksApiSubnetName = 'aks-api'
var aksNodeSubnetName = 'aks-node'
var azureFirewallSubnetName = 'AzureFirewallSubnet'
var azureFirewallPublicIpCount = 1
var amplsPrivateDnsZoneNames = [
  'privatelink.monitor.azure.com'
  'privatelink.oms.opinsights.azure.com'
  'privatelink.ods.opinsights.azure.com'
  'privatelink.agentsvc.azure-automation.net'
  'privatelink.blob.${environment().suffixes.storage}'
]
var aksClusterName = '${prefix}-aks'
var app1AksNamespaceName = 'app1'
var app1ServiceAccountName = 'app1'

resource logAnalyticsWorkspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: '${prefix}-log-analytics-workspace'
  location: location
  tags: tags
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 30
  }
}

resource privateLinkScope 'microsoft.insights/privateLinkScopes@2021-07-01-preview' = {
  name: 'ampls'
  location: 'global'
  properties: {
    accessModeSettings: {
      ingestionAccessMode: 'Open'
      queryAccessMode: 'Open'
    }
  }
}

resource privateLinkScopePrivateEndpoint 'Microsoft.Network/privateEndpoints@2024-05-01' = {
  name: '${privateLinkScope.name}-azuremonitor-private-endpoint'
  location: location
  tags: tags
  properties: {
    customNetworkInterfaceName: '${privateLinkScope.name}-azuremonitor-nic'
    subnet: {
      id: privateLinkSubnet.id
    }
    privateLinkServiceConnections: [
      {
        name: 'azuremonitor'
        properties: {
          privateLinkServiceId: privateLinkScope.id
          groupIds: [
            'azuremonitor'
          ]
        }
      }
    ]
  }
}

resource privateLinkScopePrivateDnsZoneGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-05-01' = {
  name: 'private-dns-zone-group'
  parent: privateLinkScopePrivateEndpoint
  properties: {
    privateDnsZoneConfigs: [
      for (_, index) in amplsPrivateDnsZoneNames: {
        name: amplsPrivateDnsZones[index].name
        properties: {
          privateDnsZoneId: amplsPrivateDnsZones[index].id
        }
      }
    ]
  }
}

resource amplsLogAnalyticsScope 'Microsoft.Insights/privateLinkScopes/scopedResources@2021-07-01-preview' = {
  name: logAnalyticsWorkspace.name
  parent: privateLinkScope
  properties: {
    linkedResourceId: logAnalyticsWorkspace.id
  }
}

resource amplsPrivateDnsZones 'Microsoft.Network/privateDnsZones@2024-06-01' = [
  for item in amplsPrivateDnsZoneNames: {
    name: item
    location: 'global'
    tags: tags
    properties: {}
  }
]

resource amplsPrivateDnsZoneLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = [
  for (_, index) in amplsPrivateDnsZoneNames: {
    name: virtualNetwork.name
    parent: amplsPrivateDnsZones[index]
    location: 'global'
    properties: {
      registrationEnabled: false
      virtualNetwork: {
        id: virtualNetwork.id
      }
    }
  }
]

resource linuxDataCollectionEndpoint 'Microsoft.Insights/dataCollectionEndpoints@2023-03-11' = {
  name: 'linux-data-collection-endpoint'
  location: location
  tags: tags
  kind: 'Linux'
  properties: {
    networkAcls: {
      publicNetworkAccess: 'Enabled'
    }
  }
}

resource amplsLinuxDataCollectionEndpointScope 'Microsoft.Insights/privateLinkScopes/scopedResources@2021-07-01-preview' = {
  name: linuxDataCollectionEndpoint.name
  parent: privateLinkScope
  properties: {
    linkedResourceId: linuxDataCollectionEndpoint.id
  }
}

resource routeTable 'Microsoft.Network/routeTables@2024-05-01' = {
  name: '${prefix}-route-table'
  location: location
  tags: tags
  properties: {}
}

resource routeTableInternetRoute 'Microsoft.Network/routeTables/routes@2024-05-01' = {
  name: 'internet-route'
  parent: routeTable
  properties: {
    addressPrefix: '0.0.0.0/0'
    nextHopType: 'VirtualAppliance'
    nextHopIpAddress: azureFirewall.properties.ipConfigurations[0].properties.privateIPAddress
  }
}

resource virtualNetwork 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  name: '${prefix}-virtual-network'
  location: location
  tags: tags
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.0.0.0/24'
      ]
    }
    subnets: [
      {
        name: privateLinkSubnetName
        properties: {
          addressPrefix: '10.0.0.0/27'
          routeTable: {
            id: routeTable.id
          }
        }
      }
      {
        name: aksApiSubnetName
        properties: {
          addressPrefix: '10.0.0.32/28'
          routeTable: {
            id: routeTable.id
          }
          delegations: [
            {
              name: 'Microsoft.ContainerService/managedClusters'
              properties: {
                serviceName: 'Microsoft.ContainerService/managedClusters'
              }
            }
          ]
        }
      }
      {
        name: aksNodeSubnetName
        properties: {
          addressPrefix: '10.0.0.64/26'
          routeTable: {
            id: routeTable.id
          }
        }
      }
      {
        name: azureFirewallSubnetName
        properties: {
          addressPrefix: '10.0.0.128/26'
        }
      }
    ]
  }
}

module vnetFlowLogs 'vnet-flow-logs.bicep' = {
  name: 'vnet-flow-logs-deployment'
  scope: resourceGroup('NetworkWatcherRG')
  params: {
    location: location
    logAnalyticsWorkspaceId: logAnalyticsWorkspace.id
    networkWatcherName: 'NetworkWatcher_${location}'
    storageAccountId: storageAccount.id
    virtualNetworkId: virtualNetwork.id
  }
}

resource privateLinkSubnet 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' existing = {
  name: privateLinkSubnetName
  parent: virtualNetwork
}

resource aksApiSubnet 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' existing = {
  name: aksApiSubnetName
  parent: virtualNetwork
}

resource aksNodeSubnet 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' existing = {
  name: aksNodeSubnetName
  parent: virtualNetwork
}

resource networkContributorRoleDefinition 'Microsoft.Authorization/roleDefinitions@2022-05-01-preview' existing = {
  name: '4d97b98b-1d4f-4787-a291-c67834d212e7'
  scope: subscription()
}

resource aksApiSubnetRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(aksIdentity.id, aksApiSubnet.id, networkContributorRoleDefinition.id)
  scope: aksApiSubnet
  properties: {
    principalId: aksIdentity.properties.principalId
    roleDefinitionId: networkContributorRoleDefinition.id
    principalType: 'ServicePrincipal'
  }
}

resource aksNodeSubnetRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(aksIdentity.id, aksNodeSubnet.id, networkContributorRoleDefinition.id)
  scope: aksNodeSubnet
  properties: {
    principalId: aksIdentity.properties.principalId
    roleDefinitionId: networkContributorRoleDefinition.id
    principalType: 'ServicePrincipal'
  }
}

resource azureFirewallSubnet 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' existing = {
  name: azureFirewallSubnetName
  parent: virtualNetwork
}

resource azureFirewallPublicIps 'Microsoft.Network/publicIPAddresses@2023-09-01' = [
  for index in range(0, azureFirewallPublicIpCount): {
    name: '${prefix}-azure-firewall-public-ip-${index + 1}'
    location: location
    zones: [
      '1'
      '2'
      '3'
    ]
    sku: {
      name: 'Standard'
    }
    properties: {
      publicIPAllocationMethod: 'Static'
      publicIPAddressVersion: 'IPv4'
    }
  }
]

resource azureFirewall 'Microsoft.Network/azureFirewalls@2024-05-01' = {
  name: '${prefix}-azure-firewall'
  location: location
  tags: tags
  zones: [
    '1'
    '2'
    '3'
  ]
  properties: {
    sku: {
      name: 'AZFW_VNet'
      tier: 'Standard'
    }
    ipConfigurations: [
      for index in range(0, azureFirewallPublicIpCount): {
        name: 'ip-configuration-${index + 1}'
        properties: {
          subnet: index == 0
            ? {
                id: azureFirewallSubnet.id
              }
            : null
          publicIPAddress: {
            id: azureFirewallPublicIps[index].id
          }
        }
      }
    ]
    firewallPolicy: {
      id: firewallPolicy.id
    }
  }
}

resource firewallDiagnosticSettings 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'enable-all'
  scope: azureFirewall
  properties: {
    logAnalyticsDestinationType: 'Dedicated'
    workspaceId: logAnalyticsWorkspace.id
    logs: [
      {
        categoryGroup: 'allLogs'
        enabled: true
      }
    ]
  }
}

resource firewallPolicy 'Microsoft.Network/firewallPolicies@2024-05-01' = {
  name: '${prefix}-firewall-policy'
  location: location
  tags: tags
  properties: {}
}

resource networkCollectionRule 'Microsoft.Network/firewallPolicies/ruleCollectionGroups@2024-05-01' = {
  name: 'default-network-collection-rule'
  parent: firewallPolicy
  properties: {
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
}

resource privateDnsZone 'Microsoft.Network/privateDnsZones@2024-06-01' = {
  name: '${prefix}.contoso.com'
  location: 'global'
  tags: tags
  properties: {}
}

resource privateDnsZoneContributorRoleDefinition 'Microsoft.Authorization/roleDefinitions@2018-01-01-preview' existing = {
  scope: subscription()
  name: 'b12aa53e-6015-4669-85d0-8515ebb3ae7f'
}

resource privateDnsZoneContributorAksAppRoutingRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid('app-routing-addon', aksCluster.id, privateDnsZone.id, privateDnsZoneContributorRoleDefinition.id)
  scope: privateDnsZone
  properties: {
    principalId: aksCluster.properties.ingressProfile.webAppRouting.identity.objectId
    roleDefinitionId: privateDnsZoneContributorRoleDefinition.id
    principalType: 'ServicePrincipal'
  }
}

resource privateDnsZoneLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = {
  name: virtualNetwork.name
  parent: privateDnsZone
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: virtualNetwork.id
    }
  }
}

resource aksIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${aksClusterName}-identity'
  location: location
  tags: tags
}

resource aksDataCollectionRule 'Microsoft.Insights/dataCollectionRules@2023-03-11' = {
  name: '${aksClusterName}-data-collection-rule'
  location: location
  tags: tags
  kind: 'Linux'
  properties: {
    dataCollectionEndpointId: linuxDataCollectionEndpoint.id
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
          workspaceResourceId: logAnalyticsWorkspace.id
          name: logAnalyticsWorkspace.name
        }
      ]
    }
    dataFlows: [
      {
        streams: [
          'Microsoft-ContainerInsights-Group-Default'
        ]
        destinations: [
          logAnalyticsWorkspace.name
        ]
      }
    ]
  }
}

resource aksDataCollectionRuleAssociation 'Microsoft.Insights/dataCollectionRuleAssociations@2023-03-11' = {
  name: '${aksDataCollectionRule.name}-association'
  scope: aksCluster
  properties: {
    dataCollectionRuleId: aksDataCollectionRule.id
  }
}

resource aksDataCollectionEndpointAssociation 'Microsoft.Insights/dataCollectionRuleAssociations@2023-03-11' = {
  name: 'configurationAccessEndpoint'
  scope: aksCluster
  properties: {
    dataCollectionEndpointId: linuxDataCollectionEndpoint.id
  }
}

resource aksCluster 'Microsoft.ContainerService/managedClusters@2024-09-02-preview' = {
  name: aksClusterName
  dependsOn: [
    aksApiSubnetRoleAssignment
    aksNodeSubnetRoleAssignment
    routeTableInternetRoute
  ]
  location: location
  tags: tags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${aksIdentity.id}': {}
    }
  }
  sku: {
    name: 'Base'
    tier: 'Standard'
  }
  properties: {
    nodeResourceGroup: '${aksClusterName}-mrg'
    enableRBAC: false
    kubernetesVersion: '1.31.2'
    autoUpgradeProfile: {
      upgradeChannel: 'patch'
    }
    dnsPrefix: aksClusterName
    publicNetworkAccess: 'Disabled'
    networkProfile: {
      networkPlugin: 'azure'
      networkPluginMode: 'overlay'
      networkPolicy: 'calico'
      outboundType: 'userDefinedRouting'
      dnsServiceIP: '10.1.0.10'
      serviceCidr: '10.1.0.0/16'
    }
    apiServerAccessProfile: {
      enablePrivateCluster: true
      enableVnetIntegration: true
      enablePrivateClusterPublicFQDN: true
      subnetId: aksApiSubnet.id
      privateDNSZone: 'none'
    }
    securityProfile: {
      workloadIdentity: {
        enabled: true
      }
    }
    oidcIssuerProfile: {
      enabled: true
    }
    ingressProfile: {
      webAppRouting: {
        enabled: true
        dnsZoneResourceIds: [
          privateDnsZone.id
        ]
        nginx: {
          defaultIngressControllerType: 'Internal'
        }
      }
    }
    agentPoolProfiles: [
      {
        name: 'system'
        osDiskSizeGB: 128
        vmSize: 'Standard_D2ads_v6'
        osType: 'Linux'
        mode: 'System'
        enableAutoScaling: true
        vnetSubnetID: aksNodeSubnet.id
        minCount: 1
        count: 1
        maxCount: 10
        osDiskType: 'Managed'
        availabilityZones: [
          '1'
          '2'
        ]
      }
      {
        name: 'user1'
        osDiskSizeGB: 128
        vmSize: 'Standard_D2ads_v6'
        osType: 'Linux'
        mode: 'User'
        enableAutoScaling: true
        vnetSubnetID: aksNodeSubnet.id
        spotMaxPrice: -1
        minCount: 0
        count: 0
        maxCount: 20
        osDiskType: 'Managed'
        availabilityZones: [
          '1'
          '2'
        ]
      }
    ]
    workloadAutoScalerProfile: {
      keda: {
        enabled: true
      }
    }
    addonProfiles: {
      azureKeyvaultSecretsProvider: {
        config: {
          enableSecretRotation: 'true'
        }
        enabled: true
      }
      omsAgent: {
        enabled: true
        config: {
          logAnalyticsWorkspaceResourceID: logAnalyticsWorkspace.id
          useAADAuth: 'true'
        }
      }
    }
  }
}

resource keyVault 'Microsoft.KeyVault/vaults@2024-04-01-preview' = {
  name: '${shortPrefix}-vault'
  location: location
  tags: tags
  properties: {
    enabledForDeployment: true
    enabledForTemplateDeployment: true
    enableSoftDelete: true
    enableRbacAuthorization: true
    sku: {
      name: 'standard'
      family: 'A'
    }
    tenantId: subscription().tenantId
    networkAcls: {
      defaultAction: 'Deny'
      bypass: 'AzureServices'
      ipRules: [
        for address in allowedIpAddresses: {
          value: address
        }
      ]
    }
  }
}

resource keyVaultPrivateDnsZone 'Microsoft.Network/privateDnsZones@2024-06-01' = {
  name: 'privatelink${environment().suffixes.keyvaultDns}'
  location: 'global'
  tags: tags
  properties: {}
}

resource keyVaultPrivateDnsZoneLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = {
  name: virtualNetwork.name
  parent: keyVaultPrivateDnsZone
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: virtualNetwork.id
    }
  }
}

resource keyVaultPrivateEndpoint 'Microsoft.Network/privateEndpoints@2024-05-01' = {
  name: '${keyVault.name}-vault-pep'
  location: location
  tags: tags
  properties: {
    subnet: {
      id: privateLinkSubnet.id
    }
    customNetworkInterfaceName: '${keyVault.name}-vault-nic'
    privateLinkServiceConnections: [
      {
        name: 'vault'
        properties: {
          privateLinkServiceId: keyVault.id
          groupIds: [
            'vault'
          ]
        }
      }
    ]
  }
}

resource keyVaultPrivateEndpointDnsZoneGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-05-01' = {
  name: 'private-dns-zone-group'
  parent: keyVaultPrivateEndpoint
  properties: {
    privateDnsZoneConfigs: [
      {
        name: keyVaultPrivateDnsZone.name
        properties: {
          privateDnsZoneId: keyVaultPrivateDnsZone.id
        }
      }
    ]
  }
}

resource keyVaultDiagnosticSettings 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'enable-all'
  scope: keyVault
  properties: {
    logs: [
      {
        categoryGroup: 'allLogs'
        enabled: true
      }
    ]
    logAnalyticsDestinationType: 'Dedicated'
    workspaceId: logAnalyticsWorkspace.id
  }
}

resource keyVaultCertificatesOfficerRoleDefinition 'Microsoft.Authorization/roleDefinitions@2018-01-01-preview' existing = {
  scope: subscription()
  name: 'a4417e6f-fecd-4de8-b567-7b0420556985'
}

resource keyVaultSecretsUserRoleDefinition 'Microsoft.Authorization/roleDefinitions@2018-01-01-preview' existing = {
  scope: subscription()
  name: '4633458b-17de-408a-b874-0445c86b69e6'
}

resource keyVaultStorageAccountConnectionStringSecret 'Microsoft.KeyVault/vaults/secrets@2024-04-01-preview' = {
  name: 'storage-account-connection-string'
  parent: keyVault
  properties: {
    value: 'DefaultEndpointsProtocol=https;AccountName=${storageAccount.name};AccountKey=${storageAccount.listKeys().keys[0].value};EndpointSuffix=${environment().suffixes.storage}'
  }
}

resource keyVaultSecretsUserApp1RoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(app1ManagedIdentity.id, keyVault.id, keyVaultSecretsUserRoleDefinition.id)
  scope: keyVault
  properties: {
    principalId: app1ManagedIdentity.properties.principalId
    roleDefinitionId: keyVaultSecretsUserRoleDefinition.id
    principalType: 'ServicePrincipal'
  }
}

resource keyVaultSecretsUserAksAppRoutingRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid('app-routing-addon', aksCluster.id, keyVault.id, keyVaultSecretsUserRoleDefinition.id)
  scope: keyVault
  properties: {
    principalId: aksCluster.properties.ingressProfile.webAppRouting.identity.objectId
    roleDefinitionId: keyVaultSecretsUserRoleDefinition.id
    principalType: 'ServicePrincipal'
  }
}

resource deployerKeyVaultCertificatesOfficerRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(deployer().objectId, keyVault.id, keyVaultCertificatesOfficerRoleDefinition.id)
  scope: keyVault
  properties: {
    principalId: deployer().objectId
    roleDefinitionId: keyVaultCertificatesOfficerRoleDefinition.id
  }
}

resource storageAccount 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: toLower('${shortAlphanumericPrefix}stor')
  location: location
  tags: tags
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    accessTier: 'Hot'
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false
    networkAcls: {
      bypass: 'AzureServices'
      defaultAction: 'Deny'
    }
    supportsHttpsTrafficOnly: true
  }
}

resource storageAccountBlobServices 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  name: 'default'
  parent: storageAccount
  properties: {
    containerDeleteRetentionPolicy: {
      enabled: true
      days: 30
    }
    deleteRetentionPolicy: {
      enabled: true
      days: 30
    }
  }
}

resource storageAccountBlobServicesDiagnosticSettings 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'enable-all'
  scope: storageAccountBlobServices
  properties: {
    logs: [
      {
        categoryGroup: 'AllLogs'
        enabled: true
      }
    ]
    logAnalyticsDestinationType: 'Dedicated'
    workspaceId: logAnalyticsWorkspace.id
  }
}

resource storageAccountBlobPrivateEndpoint 'Microsoft.Network/privateEndpoints@2024-05-01' = {
  name: '${storageAccount.name}-blob-pep'
  location: location
  tags: tags
  properties: {
    customNetworkInterfaceName: '${storageAccount.name}-blob-nic'
    subnet: {
      id: privateLinkSubnet.id
    }
    privateLinkServiceConnections: [
      {
        name: 'blob'
        properties: {
          privateLinkServiceId: storageAccount.id
          groupIds: ['blob']
        }
      }
    ]
  }
}

resource storageAccountPrivateDnsZone 'Microsoft.Network/privateDnsZones@2024-06-01' existing = {
  name: 'privatelink.blob.${environment().suffixes.storage}'
  dependsOn: amplsPrivateDnsZones
}

resource storageAccountPrivateEndpointDnsZoneGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-05-01' = {
  name: 'private-dns-zone-group'
  parent: storageAccountBlobPrivateEndpoint
  properties: {
    privateDnsZoneConfigs: [
      {
        name: storageAccountPrivateDnsZone.name
        properties: {
          privateDnsZoneId: storageAccountPrivateDnsZone.id
        }
      }
    ]
  }
}

resource app1ManagedIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${aksClusterName}-app1-identity'
  location: location
  tags: tags
}

resource app1ManagedIdentityFederatedCredentials 'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials@2023-01-31' = {
  name: '${aksClusterName}-federated-credentials'
  parent: app1ManagedIdentity
  properties: {
    audiences: [
      'api://AzureADTokenExchange'
    ]
    issuer: aksCluster.properties.oidcIssuerProfile.issuerURL
    subject: 'system:serviceaccount:${app1AksNamespaceName}:${app1ServiceAccountName}'
  }
}

output dnsZoneName string = privateDnsZone.name
output aksClusterName string = aksCluster.name
output keyVaultName string = keyVault.name
output keyVaultUrl string = keyVault.properties.vaultUri
output keyVaultStorageAccountConnectionStringSecretName string = keyVaultStorageAccountConnectionStringSecret.name
output app1ManagedIdentityClientId string = app1ManagedIdentity.properties.clientId
output app1AksNamespaceName string = app1AksNamespaceName
output app1ServiceAccountName string = app1ServiceAccountName
