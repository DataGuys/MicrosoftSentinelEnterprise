## Network Security Architecture Guide

```markdown
# Network Security Guide for Enterprise Sentinel

This guide outlines the network security architecture and best practices for deploying Azure Sentinel in an enterprise environment with advanced security requirements.

## Reference Architecture

The following network security architecture is recommended for Enterprise Sentinel deployments:

![Network Security Architecture](docs/images/network-architecture.png)

## Azure Firewall Integration

### Firewall Deployment

Deploy Azure Firewall in a hub-spoke architecture to secure Sentinel-related traffic:

```bicep
// Azure Firewall deployment
resource azureFirewall 'Microsoft.Network/azureFirewalls@2023-04-01' = {
  name: '${prefix}-hub-firewall'
  location: location
  properties: {
    sku: {
      name: 'AZFW_VNet'
      tier: 'Premium'
    }
    threatIntelMode: 'Deny'
    ipConfigurations: [
      {
        name: 'ipConfig'
        properties: {
          subnet: {
            id: '${hubVnetId}/subnets/AzureFirewallSubnet'
          }
          publicIPAddress: {
            id: firewallPublicIP.id
          }
        }
      }
    ]
  }
}
