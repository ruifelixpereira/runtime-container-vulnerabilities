targetScope = 'subscription'

resource defenderContainers 'Microsoft.Security/pricings@2024-01-01' = {
  name: 'Containers'
  properties: {
    pricingTier: 'Standard'
  }
}

resource defenderContainerRegistry 'Microsoft.Security/pricings@2024-01-01' = {
  name: 'ContainerRegistry'
  properties: {
    pricingTier: 'Standard'
  }
}

output defenderContainersEnabled bool = defenderContainers.properties.pricingTier == 'Standard'
