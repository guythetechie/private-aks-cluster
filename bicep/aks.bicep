type DataCollectionRuleAssociation = {
  name: string
  dataCollectionRuleId: string?
  dataCollectionEndpointId: string?
}

param name string
param location string
param tags object
param logAnalyticsWorkspaceResourceId string
param identityResourceId string
param apiSubnetResourceId string
param nodeSubnetResourceId string
param privateDnsZoneResourceId string
param dataCollectionRuleAssociations DataCollectionRuleAssociation[] = []

resource cluster 'Microsoft.ContainerService/managedClusters@2024-09-02-preview' = {
  name: name
  location: location
  tags: tags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${identityResourceId}': {}
    }
  }
  sku: {
    name: 'Base'
    tier: 'Standard'
  }
  properties: {
    nodeResourceGroup: '${name}-mrg'
    enableRBAC: false
    kubernetesVersion: '1.31.2'
    autoUpgradeProfile: {
      upgradeChannel: 'patch'
    }
    dnsPrefix: name
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
      subnetId: apiSubnetResourceId
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
          privateDnsZoneResourceId
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
        vnetSubnetID: nodeSubnetResourceId
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
        vnetSubnetID: nodeSubnetResourceId
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
          logAnalyticsWorkspaceResourceID: logAnalyticsWorkspaceResourceId
          useAADAuth: 'true'
        }
      }
    }
  }
}

resource dataCollectionRuleAssociation 'Microsoft.Insights/dataCollectionRuleAssociations@2023-03-11' = [
  for association in dataCollectionRuleAssociations: {
    name: association.name
    scope: cluster
    properties: {
      #disable-next-line use-resource-id-functions
      dataCollectionRuleId: association.?dataCollectionRuleId
      #disable-next-line use-resource-id-functions
      dataCollectionEndpointId: association.?dataCollectionEndpointId
    }
  }
]

output name string = cluster.name
output resourceId string = cluster.id
output ingressPrincipalId string = cluster.properties.ingressProfile.webAppRouting.identity.objectId
output kubeletIdentityPrincipalId string = cluster.properties.identityProfile.kubeletIdentity.objectId
output oidcIssuerProfileUrl string = cluster.properties.oidcIssuerProfile.issuerURL
