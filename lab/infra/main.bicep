targetScope = 'subscription'

@description('Location for all resources')
param location string = 'westeurope'

@description('Base name prefix for all resources')
param baseName string = 'cvulnlab'

@description('Admin username for the VM')
param adminUsername string = 'azureuser'

@description('SSH public key for VM access')
@secure()
param sshPublicKey string

@description('VM size')
param vmSize string = 'Standard_D2s_v3'

// Resource group
resource rg 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: '${baseName}-rg'
  location: location
}

// Enable Defender for Containers at subscription level
module defender 'modules/defender.bicep' = {
  name: 'defender-deployment'
  scope: subscription()
}

// Networking
module network 'modules/network.bicep' = {
  name: 'network-deployment'
  scope: rg
  params: {
    location: location
    baseName: baseName
  }
}

// Azure Container Registry
module acr 'modules/acr.bicep' = {
  name: 'acr-deployment'
  scope: rg
  params: {
    location: location
    baseName: baseName
  }
}

// VM with k3s
module vm 'modules/vm.bicep' = {
  name: 'vm-deployment'
  scope: rg
  params: {
    location: location
    baseName: baseName
    subnetId: network.outputs.subnetId
    publicIpId: network.outputs.publicIpId
    adminUsername: adminUsername
    sshPublicKey: sshPublicKey
    vmSize: vmSize
  }
}

output resourceGroupName string = rg.name
output vmPublicIp string = network.outputs.publicIpAddress
output vmName string = vm.outputs.vmName
output acrName string = acr.outputs.acrName
output acrLoginServer string = acr.outputs.acrLoginServer
output adminUsername string = adminUsername
