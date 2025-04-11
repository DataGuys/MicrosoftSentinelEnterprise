// Workspaces Module - Deploys Sentinel and auxiliary workspaces with optional LA Cluster
@description('The location for all resources')
param location string

@description('Prefix to use for resource naming')
param prefix string

@description('Tags to apply to all resources')
param tags object

@description('Default retention days for Log Analytics Workspaces')
param defaultRetentionDays int

@description('Archive retention days for verbose/archive workspace')
param verboseRetentionDays int

@description('Retention days for staging workspace')
param stagingRetentionDays int

@description('Pricing tier for the central Sentinel workspace')
param sentinelWorkspaceSku string

@description('Pricing tier for the verbose workspace')
param verboseWorkspaceSku string

@description('Daily cap for the central Sentinel workspace in GB')
param sentinelDailyCap int

@description('Daily cap for the verbose workspace in GB')
param verboseDailyCap int

@description('Daily cap for the staging workspace in GB')
param stagingDailyCap int

@description('Flag to deploy a Log Analytics Cluster instead of regular workspaces')
param useLogAnalyticsCluster bool

@description('Capacity reservation in GB per day for the Log Analytics Cluster')
param laClusterCapacityReservationGB int

@description('Enable Customer-Managed Keys for encryption')
param enableCustomerManagedKey bool

@description('Key Vault ID containing the encryption key')
param keyVaultId string

@description('Key name in the Key Vault')
param keyName string

@description('Key version in the Key Vault')
param keyVersion string

// Variables
var sentinelWorkspaceName = '${prefix}-sentinel-ws'
var verboseWorkspaceName = '${prefix}-verbose-ws'
var stagingWorkspaceName = '${prefix}-staging-ws'

// --------------------- LOG ANALYTICS CLUSTER (OPTIONAL) -----------------------

// Log Analytics Cluster for high-volume environments (optional)
resource laCluster 'Microsoft.OperationalInsights/clusters@2021-06-01' = if (useLogAnalyticsCluster) {
  name: '${prefix}-la-cluster'
  location: location
  tags: tags
  properties: {
    sku: {
      name: 'CapacityReservation'
      capacity: laClusterCapacityReservationGB
    }
    keyVaultProperties: enableCustomerManagedKey ? {
      keyVaultUri: keyVaultId
      keyName: keyName
      keyVersion: keyVersion
    } : null
  }
}

// --------------------- WORKSPACES -----------------------

// 1. Central Sentinel Workspace (Analytics Tier)
resource sentinelWorkspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: sentinelWorkspaceName
  location: location
  tags: tags
  properties: {
    sku: {
      name: useLogAnalyticsCluster ? 'LACluster' : sentinelWorkspaceSku
    }
    retentionInDays: defaultRetentionDays
    workspaceCapping: {
      dailyQuotaGb: sentinelDailyCap
    }
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
      immediatePurgeDataOn30Days: false // Disabled for SOX compliance
    }
    clusterResourceId: useLogAnalyticsCluster ? laCluster.id : null
  }
}

// 2. Verbose Logs Workspace (Auxiliary Tier) for cost optimization
resource verboseWorkspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: verboseWorkspaceName
  location: location
  tags: tags
  properties: {
    sku: {
      name: useLogAnalyticsCluster ? 'LACluster' : verboseWorkspaceSku
    }
    retentionInDays: verboseRetentionDays
    workspaceCapping: {
      dailyQuotaGb: verboseDailyCap
    }
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
      immediatePurgeDataOn30Days: false // Disabled for SOX compliance
    }
    clusterResourceId: useLogAnalyticsCluster ? laCluster.id : null
  }
}

// 3. Staging Workspace for pre-processing
resource stagingWorkspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: stagingWorkspaceName
  location: location
  tags: tags
  properties: {
    sku: {
      name: useLogAnalyticsCluster ? 'LACluster' : sentinelWorkspaceSku
    }
    retentionInDays: stagingRetentionDays
    workspaceCapping: {
      dailyQuotaGb: stagingDailyCap
    }
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
      immediatePurgeDataOn30Days: false // For compliance
    }
    clusterResourceId: useLogAnalyticsCluster ? laCluster.id : null
  }
}

// Enable Microsoft Sentinel on the central workspace
resource enableSentinel 'Microsoft.SecurityInsights/onboardingStates@2023-05-01' = {
  scope: sentinelWorkspace
  name: 'default'
  properties: {}
}

// Outputs
output sentinelWorkspaceId string = sentinelWorkspace.id
output verboseWorkspaceId string = verboseWorkspace.id
output stagingWorkspaceId string = stagingWorkspace.id
output sentinelWorkspaceName string = sentinelWorkspace.name
output verboseWorkspaceName string = verboseWorkspace.name
output stagingWorkspaceName string = stagingWorkspace.name
output laClusterId string = useLogAnalyticsCluster ? laCluster.id : 'Not deployed'
