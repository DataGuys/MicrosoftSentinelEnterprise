// Data Collection Rules Module - Creates and configures DCRs and associates them with resources
@description('The location for all resources')
param location string

@description('Prefix to use for resource naming')
param prefix string

@description('Tags to apply to all resources')
param tags object

@description('Resource ID for the central Sentinel workspace')
param sentinelWorkspaceId string

@description('Resource ID for the verbose workspace')
param verboseWorkspaceId string

@description('Resource ID for the staging workspace')
param stagingWorkspaceId string

@description('Array of VM resource IDs to assign the DCRs to')
param vmResourceIds array = []

// Variables to extract workspace names for scope references
var sentinelWorkspaceName = last(split(sentinelWorkspaceId, '/'))
var verboseWorkspaceName = last(split(verboseWorkspaceId, '/'))
var stagingWorkspaceName = last(split(stagingWorkspaceId, '/'))

// --------------------- DATA COLLECTION RULES -----------------------

// 1. DCR for Windows Security Events - Critical Events to Sentinel
resource dcrSecurityEventsCritical 'Microsoft.Insights/dataCollectionRules@2022-06-01' = {
  name: '${prefix}-dcr-win-security-critical'
  location: location
  tags: tags
  properties: {
    dataCollectionEndpointId: null // Use default endpoint
    description: 'Collects critical Windows Security Events for Sentinel'
    dataSources: {
      windowsEventLogs: [
        {
          name: 'winSecurityEvents'
          streams: ['Microsoft-SecurityEvent']
          xPathQueries: ['Security!*[System[(EventID=4624 or EventID=4625 or EventID=4672 or EventID=4720 or EventID=4726 or EventID=4740 or EventID=1102 or EventID=4698 or EventID=4697 or EventID=7045)]]']
        }
      ]
    }
    destinations: {
      logAnalytics: [
        {
          workspaceResourceId: sentinelWorkspaceId
          name: 'sentinelDestination'
        }
      ]
    }
    dataFlows: [
      {
        streams: ['Microsoft-SecurityEvent']
        destinations: ['sentinelDestination']
        transformKql: 'source | where EventID in (4624, 4625, 4672, 4720, 4726, 4740, 1102, 4698, 4697, 7045)'
      }
    ]
  }
}

// 2. DCR for Windows Security Events - All Events to Verbose Workspace
resource dcrSecurityEventsAll 'Microsoft.Insights/dataCollectionRules@2022-06-01' = {
  name: '${prefix}-dcr-win-security-all'
  location: location
  tags: tags
  properties: {
    dataCollectionEndpointId: null // Use default endpoint
    description: 'Collects all Windows Security Events for verbose logging'
    dataSources: {
      windowsEventLogs: [
        {
          name: 'winSecurityEventsAll'
          streams: ['Microsoft-SecurityEvent']
          xPathQueries: ['Security!*']
        }
      ]
    }
    destinations: {
      logAnalytics: [
        {
          workspaceResourceId: verboseWorkspaceId
          name: 'verboseDestination'
        }
      ]
    }
    dataFlows: [
      {
        streams: ['Microsoft-SecurityEvent']
        destinations: ['verboseDestination']
        // No transform here - we want all events
      }
    ]
  }
}

// 3. DCR for Windows Sysmon Events - Critical to Sentinel, all to Verbose
resource dcrSysmonEvents 'Microsoft.Insights/dataCollectionRules@2022-06-01' = {
  name: '${prefix}-dcr-sysmon'
  location: location
  tags: tags
  properties: {
    dataCollectionEndpointId: null // Use default endpoint
    description: 'Collects Sysmon events'
    dataSources: {
      windowsEventLogs: [
        {
          name: 'sysmonEvents'
          streams: ['Microsoft-WindowsEvent']
          xPathQueries: ['Microsoft-Windows-Sysmon/Operational!*']
        }
      ]
    }
    destinations: {
      logAnalytics: [
        {
          workspaceResourceId: sentinelWorkspaceId
          name: 'sentinelDestination'
        },
        {
          workspaceResourceId: verboseWorkspaceId
          name: 'verboseDestination'
        }
      ]
    }
    dataFlows: [
      {
        streams: ['Microsoft-WindowsEvent']
        destinations: ['sentinelDestination']
        transformKql: 'source | where EventID in (1, 3, 7, 11, 12, 13, 22)' // Process creation, network, image load, file creation, registry, etc.
      },
      {
        streams: ['Microsoft-WindowsEvent']
        destinations: ['verboseDestination']
        // No transform - send all Sysmon events to verbose
      }
    ]
  }
}

// 4. DCR for Linux Syslog - Critical to Sentinel, all to Verbose
resource dcrLinuxSyslog 'Microsoft.Insights/dataCollectionRules@2022-06-01' = {
  name: '${prefix}-dcr-linux-syslog'
  location: location
  tags: tags
  properties: {
    dataCollectionEndpointId: null // Use default endpoint
    description: 'Collects Linux Syslog messages'
    dataSources: {
      syslog: [
        {
          name: 'sysLogDataSource'
          streams: ['Microsoft-Syslog']
          facilityNames: ['auth', 'authpriv', 'cron', 'daemon', 'security']
          logLevels: ['Emergency', 'Alert', 'Critical', 'Error', 'Warning']
        }
      ]
    }
    destinations: {
      logAnalytics: [
        {
          workspaceResourceId: sentinelWorkspaceId
          name: 'sentinelDestination'
        },
        {
          workspaceResourceId: verboseWorkspaceId
          name: 'verboseDestination'
        }
      ]
    }
    dataFlows: [
      {
        streams: ['Microsoft-Syslog']
        destinations: ['sentinelDestination']
        transformKql: 'source | where SeverityLevel <= 3 or Facility in ("auth", "authpriv", "security")'
      },
      {
        streams: ['Microsoft-Syslog']
        destinations: ['verboseDestination']
        // No transform - send all syslog to verbose
      }
    ]
  }
}

// 5. DCR for Staging Workspace - Preprocessing data
resource dcrProcessStaging 'Microsoft.Insights/dataCollectionRules@2022-06-01' = {
  name: '${prefix}-dcr-process-staging'
  location: location
  tags: tags
  properties: {
    dataCollectionEndpointId: null // Use default endpoint
    description: 'Collects data for staging/preprocessing workspace'
    dataSources: {
      windowsEventLogs: [
        {
          name: 'winVPNEvents'
          streams: ['Microsoft-WindowsEvent']
          xPathQueries: ['System!*[System[Provider[@Name="RasClient"]]]', 'System!*[System[Provider[@Name="RemoteAccess"]]]']
        }
      ]
    }
    destinations: {
      logAnalytics: [
        {
          workspaceResourceId: stagingWorkspaceId
          name: 'stagingDestination'
        }
      ]
    }
    dataFlows: [
      {
        streams: ['Microsoft-WindowsEvent']
        destinations: ['stagingDestination']
        // Optional transformation if needed
      }
    ]
  }
}

// 6. Workspace-level DCR for Azure resource diagnostics filtering
resource dcrTransformFirewallLogs 'Microsoft.Insights/dataCollectionRules@2022-06-01' = {
  name: '${prefix}-dcr-transform-firewall-logs'
  location: location
  tags: tags
  properties: {
    description: 'Transforms Azure Firewall logs to filter out noise'
    dataCollectionEndpointId: null
    streamDeclarations: {
      'Custom-AzureFirewallLogs': {
        columns: [
          {
            name: 'TimeGenerated',
            type: 'datetime'
          },
          {
            name: 'Category',
            type: 'string'
          },
          {
            name: 'OperationName',
            type: 'string'
          },
          {
            name: 'ResourceId',
            type: 'string'
          },
          {
            name: 'properties_msg',
            type: 'dynamic'
          }
        ]
      }
    }
    destinations: {
      logAnalytics: [
        {
          workspaceResourceId: sentinelWorkspaceId
          name: 'sentinelDestination'
        }
      ]
    }
    dataFlows: [
      {
        streams: ['Custom-AzureFirewallLogs'],
        destinations: ['sentinelDestination'],
        transformKql: 'source | where Category == "AzureFirewallApplicationRule" or Category == "AzureFirewallNetworkRule" | where OperationName == "AzureFirewallApplicationRuleLog" or OperationName == "AzureFirewallNetworkRuleLog" | where properties_msg has_any ("Deny", "ThreatIntel", "IDS", "Alert")'
      }
    ]
  }
}

// --------------------- DCR ASSOCIATIONS -----------------------

// Associate DCRs with VMs - process associations one at a time
@batchSize(1)
resource dcrAssociationSecurityCritical 'Microsoft.Insights/dataCollectionRuleAssociations@2022-06-01' = [for (vmId, i) in vmResourceIds: {
  name: '${prefix}-dcra-security-critical-${i}'
  properties: {
    dataCollectionRuleId: dcrSecurityEventsCritical.id
    description: 'Association of critical security events DCR with VM'
  }
  scope: resourceId('Microsoft.Compute/virtualMachines', vmId)
}]

@batchSize(1)
resource dcrAssociationSecurityAll 'Microsoft.Insights/dataCollectionRuleAssociations@2022-06-01' = [for (vmId, i) in vmResourceIds: {
  name: '${prefix}-dcra-security-all-${i}'
  properties: {
    dataCollectionRuleId: dcrSecurityEventsAll.id
    description: 'Association of all security events DCR with VM'
  }
  scope: resourceId('Microsoft.Compute/virtualMachines', vmId)
}]

@batchSize(1)
resource dcrAssociationSysmon 'Microsoft.Insights/dataCollectionRuleAssociations@2022-06-01' = [for (vmId, i) in vmResourceIds: {
  name: '${prefix}-dcra-sysmon-${i}'
  properties: {
    dataCollectionRuleId: dcrSysmonEvents.id
    description: 'Association of Sysmon DCR with VM'
  }
  scope: resourceId('Microsoft.Compute/virtualMachines', vmId)
}]

// Output DCR IDs for reference
output securityEventsCriticalDcrId string = dcrSecurityEventsCritical.id
output securityEventsAllDcrId string = dcrSecurityEventsAll.id
output sysmonEventsDcrId string = dcrSysmonEvents.id
output linuxSyslogDcrId string = dcrLinuxSyslog.id
output stagingDcrId string = dcrProcessStaging.id
output firewallLogsDcrId string = dcrTransformFirewallLogs.id
