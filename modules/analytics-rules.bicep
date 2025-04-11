// Analytics Rules Module - Deploys Sentinel content like rules and connectors
@description('Prefix to use for resource naming')
param prefix string

@description('Name of the central Sentinel workspace')
param sentinelWorkspaceName string

@description('Name of the staging workspace')
param stagingWorkspaceName string

// Variables for connectors
var wdxrConnectorName = 'MicrosoftThreatProtection'

// Reference to Sentinel workspace (for scoping)
resource sentinelWorkspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: sentinelWorkspaceName
}

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
}

// Output connector and rule IDs for reference
output defenderXdrConnectorId string = defenderXdrConnector.id
output impossibleTravelRuleId string = impossibleTravelRule.id
output criticalWindowsEventsRuleId string = criticalWindowsEventsRule.id
