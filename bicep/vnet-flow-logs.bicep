param networkWatcherName string
param location string
param logAnalyticsWorkspaceId string
param storageAccountId string
param virtualNetworkId string

resource networkWatcher 'Microsoft.Network/networkWatchers@2020-11-01' existing = {
  name: networkWatcherName
}

resource vnetFlowLogs 'Microsoft.Network/networkWatchers/flowLogs@2024-05-01' = {
  name: 'vnet-flow-logs'
  parent: networkWatcher
  location: location
  properties: {
    enabled: true
    flowAnalyticsConfiguration: {
      networkWatcherFlowAnalyticsConfiguration: {
        enabled: true
        trafficAnalyticsInterval: 10
        workspaceResourceId: logAnalyticsWorkspaceId
      }
    }
    retentionPolicy: {
      days: 30
      enabled: true
    }
    storageId: storageAccountId
    targetResourceId: virtualNetworkId
  }
}
