// Multi-Workspace Azure Sentinel Architecture - Bicep Template
// This template deploys a tiered Azure Sentinel logging architecture with:
// - Central Sentinel workspace (Analytics tier)
// - Verbose logs workspace (Auxiliary/Basic tier)
// - Staging workspace for preprocessing
// - Data Collection Rules (DCRs) with transformations
// - Microsoft Defender XDR integration

// Parameters
@description('The location for all resources')
param location string = resourceGroup().location

@description('Prefix to use for resource naming')
param prefix string = 'sec'

@description('Tags to apply to all resources')
param tags object = {
  environment: 'production'
  managedBy: 'security-team'
  workload: 'security-monitoring'
}

@description('Default retention days for Log Analytics Workspaces')
param defaultRetentionDays int = 90

@description('Retention days for verbose/archive workspace')
param verboseRetentionDays int = 365

@description('Retention days for staging workspace')
param stagingRetentionDays int = 30

@description('Pricing tier for the central Sentinel workspace')
@allowed([
  'CapacityReservation'
  'Free'
  'LACluster'
  'PerGB2018'
  'PerNode'
  'Premium'
  'Standalone'
])
param sentinelWorkspaceSku string = 'PerGB2018'

@description('Pricing tier for the verbose workspace')
@allowed([
  'CapacityReservation'
  'Free'
  'LACluster'
  'PerGB2018'
  'PerNode'
  'Premium'
  'Standalone'
  'Basic' // For Auxiliary logs tier
])
param verboseWorkspaceSku string = 'Basic' // Use the new Auxiliary/Basic tier for cost savings

@description('Daily cap for the central Sentinel workspace in GB')
param sentinelDailyCap int = 0 // 0 means no cap

@description('Daily cap for the verbose workspace in GB')
param verboseDailyCap int = 0 // 0 means no cap

@description('Daily cap for the staging workspace in GB')
param stagingDailyCap int = 0 // 0 means no cap

@description('Array of VM resource IDs to assign the DCRs to')
param vmResourceIds array = []

// Variables
var sentinelWorkspaceName = '${prefix}-sentinel-ws'
var verboseWorkspaceName = '${prefix}-verbose-ws'
var stagingWorkspaceName = '${prefix}-staging-ws'
var wdxrConnectorName = 'MicrosoftThreatProtection'

// --------------------- WORKSPACES -----------------------

// 1. Central Sentinel Workspace (Analytics Tier)
resource sentinelWorkspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: sentinelWorkspaceName
  location: location
  tags: tags
  properties: {
    sku: {
      name: sentinelWorkspaceSku
    }
    retentionInDays: defaultRetentionDays
    workspaceCapping: {
      dailyQuotaGb: sentinelDailyCap
    }
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
    }
  }
}

// 2. Verbose Logs Workspace (Auxiliary Tier) for cost optimization
resource verboseWorkspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: verboseWorkspaceName
  location: location
  tags: tags
  properties: {
    sku: {
      name: verboseWorkspaceSku
    }
    retentionInDays: verboseRetentionDays
    workspaceCapping: {
      dailyQuotaGb: verboseDailyCap
    }
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
    }
  }
}

// 3. Staging Workspace for pre-processing
resource stagingWorkspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: stagingWorkspaceName
  location: location
  tags: tags
  properties: {
    sku: {
      name: sentinelWorkspaceSku // Using same SKU as Sentinel for query performance
    }
    retentionInDays: stagingRetentionDays
    workspaceCapping: {
      dailyQuotaGb: stagingDailyCap
    }
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
    }
  }
}

// Enable Microsoft Sentinel on the central workspace
resource enableSentinel 'Microsoft.SecurityInsights/onboardingStates@2023-05-01' = {
  scope: sentinelWorkspace
  name: 'default'
  properties: {}
}

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
          workspaceResourceId: sentinelWorkspace.id
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
          workspaceResourceId: verboseWorkspace.id
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
          workspaceResourceId: sentinelWorkspace.id
          name: 'sentinelDestination'
        },
        {
          workspaceResourceId: verboseWorkspace.id
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
          workspaceResourceId: sentinelWorkspace.id
          name: 'sentinelDestination'
        },
        {
          workspaceResourceId: verboseWorkspace.id
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
          workspaceResourceId: stagingWorkspace.id
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
          },
          // Add other columns as needed
        ]
      }
    }
    destinations: {
      logAnalytics: [
        {
          workspaceResourceId: sentinelWorkspace.id
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

// Associate DCRs with VMs - in a real environment you'd use a loop over vmResourceIds
// This is a simplified example for one VM

@batchSize(1) // Process associations one at a time
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

// --------------------- SENTINEL CONTENT -----------------------

// 1. Microsoft Defender XDR Data Connector
resource defenderXdrConnector 'Microsoft.SecurityInsights/dataConnectors@2022-11-01' = {
  name: wdxrConnectorName
  scope: sentinelWorkspace
  kind: 'MicrosoftThreatProtection'
  properties: {
    tenantId: subscription().tenantId
    dataTypes: {
      incidents: {
        state: 'enabled'
      }
    }
  }
  dependsOn: [
    enableSentinel // Make sure Sentinel is enabled first
  ]
}

// 2. Analytics Rule - Cross-Workspace Example (Impossible Travel)
resource impossibleTravelRule 'Microsoft.SecurityInsights/alertRules@2023-05-01' = {
  name: guid('${prefix}-rule-impossible-travel')
  kind: 'Scheduled'
  scope: sentinelWorkspace
  properties: {
    displayName: 'Impossible Travel Detection - Cross Workspace'
    description: 'This rule detects when a user logs in from two geographically distant locations within a short time window'
    severity: 'Medium'
    enabled: false // Disabled by default
    query: '''
      // Get VPN logins from staging workspace 
      let vpnLogs = workspace("${stagingWorkspaceName}").WindowsEvent
      | where EventID == 20272 and EventData has "RasClient"
      | extend UserName = extract("UserName: ([^,]+)", 1, tostring(EventData))
      | where isnotempty(UserName)
      | project TimeGenerated, UserName, Computer, VpnConnection = true;
      
      // Get Azure AD logins from Sentinel workspace
      let aadLogins = SigninLogs
      | where ResultType == 0
      | project TimeGenerated, UserName = UserPrincipalName, Location, IPAddress, AADConnection = true;
      
      // Join and look for impossible travel
      vpnLogs
      | join kind=inner (aadLogins) on UserName
      | where abs(datetime_diff('minute', TimeGenerated, TimeGenerated1)) < 60 // Within 60 minutes
      | project
          UserName,
          VpnTime = TimeGenerated,
          VpnComputer = Computer,
          AadTime = TimeGenerated1,
          AadLocation = Location,
          AadIpAddress = IPAddress
      | extend AlertDetails = strcat("User ", UserName, " logged in from VPN on ", VpnComputer, " at ", VpnTime, " and from Azure AD location ", AadLocation, " at ", AadTime)
    '''
    queryFrequency: 'PT1H'
    queryPeriod: 'PT1H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT5H'
    suppressionEnabled: false
    tactics: [
      'InitialAccess'
      'LateralMovement'
    ]
    techniques: [
      'T1078' // Valid Accounts
    ]
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          {
            identifier: 'Name'
            columnName: 'UserName'
          }
        ]
      }
    ]
    alertDetailsOverride: {
      alertDisplayNameFormat: 'Impossible Travel: {{UserName}}'
      alertDescriptionFormat: 'User {{UserName}} has logged in from two distant locations in a short timeframe'
    }
    eventGroupingSettings: {
      aggregationKind: 'SingleAlert'
    }
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'PT5H'
        matchingMethod: 'AllEntities'
        groupByEntities: [
          'Account'
        ]
        groupByAlertDetails: []
        groupByCustomDetails: []
      }
    }
  }
  dependsOn: [
    enableSentinel
    stagingWorkspace
  ]
}

// 3. Analytics Rule - Detect critical Windows events
resource criticalWindowsEventsRule 'Microsoft.SecurityInsights/alertRules@2023-05-01' = {
  name: guid('${prefix}-rule-critical-windows-events')
  kind: 'Scheduled'
  scope: sentinelWorkspace
  properties: {
    displayName: 'Critical Windows Security Events'
    description: 'This rule detects critical Windows security events like account creation, privilege escalation, etc.'
    severity: 'Medium'
    enabled: false // Disabled by default
    query: '''
      SecurityEvent
      | where EventID in (4720, 4728, 4732, 4756, 4625, 4740, 4624, 4672)
      | where AccountType == "User" and not(Account has "\\$")
      | extend EventDescription = case(
          EventID == 4720, "User account created",
          EventID == 4728, "User added to privileged group",
          EventID == 4732, "User added to privileged group",
          EventID == 4756, "User added to privileged group",
          EventID == 4625, "Failed logon",
          EventID == 4740, "User account locked out",
          EventID == 4624 and AccountType == "User" and LogonType == 10, "Remote interactive logon",
          EventID == 4672, "Admin privileges assigned",
          "Other security event"
        )
      | project TimeGenerated, Computer, EventID, Account, AccountType, LogonType, Activity, EventDescription
    '''
    queryFrequency: 'PT1H'
    queryPeriod: 'PT1H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    tactics: [
      'PrivilegeEscalation'
      'InitialAccess'
      'Persistence'
    ]
    techniques: [
      'T1078' // Valid Accounts
      'T1098' // Account Manipulation
    ]
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          {
            identifier: 'Name'
            columnName: 'Account'
          }
        ]
      },
      {
        entityType: 'Host'
        fieldMappings: [
          {
            identifier: 'HostName'
            columnName: 'Computer'
          }
        ]
      }
    ]
    alertDetailsOverride: {
      alertDisplayNameFormat: '{{EventDescription}} - {{Account}}'
      alertDescriptionFormat: '{{EventDescription}} was detected for account {{Account}} on host {{Computer}}'
    }
    eventGroupingSettings: {
      aggregationKind: 'SingleAlert'
    }
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'PT5H'
        matchingMethod: 'AllEntities'
        groupByEntities: [
          'Account'
          'Host'
        ]
        groupByAlertDetails: []
        groupByCustomDetails: []
      }
    }
  }
  dependsOn: [
    enableSentinel
  ]
}

// --------------------- OPTIONAL: DIAGNOSTIC SETTINGS -----------------------

// 1. Diagnostic settings for Azure Firewall - Send to both workspaces with filtering
resource azureFirewallDiagnosticSettings 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: '${prefix}-fw-diag-settings'
  scope: resourceGroup() // This would normally scope to your Azure Firewall resource
  properties: {
    workspaceId: sentinelWorkspace.id
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
    workspaceId: verboseWorkspace.id
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

// --------------------- OUTPUTS -----------------------

output sentinelWorkspaceId string = sentinelWorkspace.id
output verboseWorkspaceId string = verboseWorkspace.id
output stagingWorkspaceId string = stagingWorkspace.id
output sentinelWorkspaceName string = sentinelWorkspace.name
output verboseWorkspaceName string = verboseWorkspace.name
output stagingWorkspaceName string = stagingWorkspace.name
