// Multi-Workspace Azure Sentinel Architecture - Main Orchestrator
// This template orchestrates the deployment of the modular Sentinel architecture

// Common Parameters
@description('The location for all resources')
param location string = resourceGroup().location

@description('Prefix to use for resource naming')
param prefix string = 'sec'

@description('Tags to apply to all resources')
param tags object = {
  environment: 'production'
  managedBy: 'security-team'
  workload: 'security-monitoring'
  complianceFrameworks: 'SOX,GDPR,CCPA'
}

// Workspace Parameters
@description('Default retention days for Log Analytics Workspaces - SOX requires 7 years (2557 days)')
param defaultRetentionDays int = 2557

@description('Archive retention days for verbose/archive workspace - SOX requires 7 years (2557 days)')
param verboseRetentionDays int = 2557

@description('Retention days for staging workspace')
param stagingRetentionDays int = 90

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

// Log Analytics Cluster Parameters
@description('Flag to deploy a Log Analytics Cluster instead of regular workspaces')
param useLogAnalyticsCluster bool = false

@description('Capacity reservation in GB per day for the Log Analytics Cluster')
param laClusterCapacityReservationGB int = 1000

@description('Enable Customer-Managed Keys for encryption')
param enableCustomerManagedKey bool = false

@description('Key Vault ID containing the encryption key (required if enableCustomerManagedKey is true)')
param keyVaultId string = ''

@description('Key name in the Key Vault (required if enableCustomerManagedKey is true)')
param keyName string = ''

@description('Key version in the Key Vault (required if enableCustomerManagedKey is true)')
param keyVersion string = ''

// VM Resource Parameters
@description('Array of VM resource IDs to assign the DCRs to')
param vmResourceIds array = []

// Deploy Workspaces and Log Analytics Cluster
module workspaces 'modules/workspaces.bicep' = {
  name: 'workspaces-deployment'
  params: {
    location: location
    prefix: prefix
    tags: tags
    defaultRetentionDays: defaultRetentionDays
    verboseRetentionDays: verboseRetentionDays
    stagingRetentionDays: stagingRetentionDays
    sentinelWorkspaceSku: sentinelWorkspaceSku
    verboseWorkspaceSku: verboseWorkspaceSku
    sentinelDailyCap: sentinelDailyCap
    verboseDailyCap: verboseDailyCap
    stagingDailyCap: stagingDailyCap
    useLogAnalyticsCluster: useLogAnalyticsCluster
    laClusterCapacityReservationGB: laClusterCapacityReservationGB
    enableCustomerManagedKey: enableCustomerManagedKey
    keyVaultId: keyVaultId
    keyName: keyName
    keyVersion: keyVersion
  }
}

// Deploy Data Collection Rules
module dataCollectionRules 'modules/data-collection-rules.bicep' = {
  name: 'dcr-deployment'
  params: {
    location: location
    prefix: prefix
    tags: tags
    sentinelWorkspaceId: workspaces.outputs.sentinelWorkspaceId
    verboseWorkspaceId: workspaces.outputs.verboseWorkspaceId
    stagingWorkspaceId: workspaces.outputs.stagingWorkspaceId
    vmResourceIds: vmResourceIds
  }
  dependsOn: [
    workspaces
  ]
}

// Deploy Sentinel Analytics Rules and Connectors
module analyticsRules 'modules/analytics-rules.bicep' = {
  name: 'analytics-rules-deployment'
  params: {
    prefix: prefix
    sentinelWorkspaceName: workspaces.outputs.sentinelWorkspaceName
    stagingWorkspaceName: workspaces.outputs.stagingWorkspaceName
  }
  dependsOn: [
    workspaces
  ]
}

// Deploy Diagnostic Settings
module diagnosticSettings 'modules/diagnostic-settings.bicep' = {
  name: 'diagnostic-settings-deployment'
  params: {
    prefix: prefix
    sentinelWorkspaceId: workspaces.outputs.sentinelWorkspaceId
    verboseWorkspaceId: workspaces.outputs.verboseWorkspaceId
  }
  dependsOn: [
    workspaces
  ]
}

// Deploy Compliance Resources
module compliance 'modules/compliance.bicep' = {
  name: 'compliance-deployment'
  params: {
    location: location
    prefix: prefix
    tags: tags
    sentinelWorkspaceName: workspaces.outputs.sentinelWorkspaceName
  }
  dependsOn: [
    workspaces
  ]
}

// Outputs
output sentinelWorkspaceId string = workspaces.outputs.sentinelWorkspaceId
output verboseWorkspaceId string = workspaces.outputs.verboseWorkspaceId
output stagingWorkspaceId string = workspaces.outputs.stagingWorkspaceId
output sentinelWorkspaceName string = workspaces.outputs.sentinelWorkspaceName
output verboseWorkspaceName string = workspaces.outputs.verboseWorkspaceName
output stagingWorkspaceName string = workspaces.outputs.stagingWorkspaceName
output laClusterId string = workspaces.outputs.laClusterId
output storageAccountId string = compliance.outputs.storageAccountId
