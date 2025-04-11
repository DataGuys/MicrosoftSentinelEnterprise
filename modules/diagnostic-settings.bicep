// Diagnostic Settings Module - Configures diagnostics for Azure resources
@description('Prefix to use for resource naming')
param prefix string

@description('Resource ID for the central Sentinel workspace')
param sentinelWorkspaceId string

@description('Resource ID for the verbose workspace')
param verboseWorkspaceId string

// --------------------- DIAGNOSTIC SETTINGS -----------------------

// 1. Diagnostic settings for Azure Firewall - Send to both workspaces with filtering
resource azureFirewallDiagnosticSettings 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: '${prefix}-fw-diag-settings'
  scope: resourceGroup() // This would normally scope to your Azure Firewall resource
  properties: {
    workspaceId: sentinelWorkspaceId
    logs: [
      {
        category: 'AzureFirewallApplicationRule'
        enabled: true
      },
      {
        category: 'AzureFirewallNetworkRule'
        enabled: true
      },
      {
        category: 'AzureFirewallDnsProxy'
        enabled: true
      }
    ]
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
      }
    ]
  }
}

// 2. Diagnostic settings for sending all logs to verbose workspace
resource azureFirewallVerboseDiagnosticSettings 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: '${prefix}-fw-verbose-diag-settings'
  scope: resourceGroup() // This would normally scope to your Azure Firewall resource
  properties: {
    workspaceId: verboseWorkspaceId
    logs: [
      {
        category: 'AzureFirewallApplicationRule'
        enabled: true
      },
      {
        category: 'AzureFirewallNetworkRule'
        enabled: true
      },
      {
        category: 'AzureFirewallDnsProxy'
        enabled: true
      },
      {
        category: 'AzureFirewallThreatIntel'
        enabled: true
      }
    ]
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
      }
    ]
  }
}

// Output diagnostic settings names for reference
output firewallDiagnosticSettingsName string = azureFirewallDiagnosticSettings.name
output firewallVerboseDiagnosticSettingsName string = azureFirewallVerboseDiagnosticSettings.name
