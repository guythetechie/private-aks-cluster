type RouteType = {
  @description('Required. Name of the route.')
  name: string

  @description('Required. Properties of the route.')
  properties: {
    @description('Required. The type of Azure hop the packet should be sent to.')
    nextHopType: ('VirtualAppliance' | 'VnetLocal' | 'Internet' | 'VirtualNetworkGateway' | 'None')

    @description('Optional. The destination CIDR to which the route applies.')
    addressPrefix: string?

    @description('Optional. The IP address packets should be forwarded to. Next hop values are only allowed in routes where the next hop type is VirtualAppliance.')
    nextHopIpAddress: string?
  }
}

param route RouteType
param routeTableName string

resource routeTable 'Microsoft.Network/routeTables@2024-05-01' existing = {
  name: routeTableName
}

resource routeTableRoute 'Microsoft.Network/routeTables/routes@2024-05-01' = {
  name: route.name
  parent: routeTable
  properties: {
    nextHopType: route.properties.nextHopType
    addressPrefix: route.properties.?addressPrefix
    nextHopIpAddress: route.properties.?nextHopIpAddress
  }
}

output name string = routeTableRoute.name
output resourceId string = routeTableRoute.id
