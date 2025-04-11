// Compliance Module - Implements compliance-specific resources
@description('The location for all resources')
param location string

@description('Prefix to use for resource naming')
param prefix string

@description('Tags to apply to all resources')
param tags object

@description('Name of the central Sentinel workspace')
param sentinelWorkspaceName string

// --------------------- DATA EXPORT FOR REGULATORY COMPLIANCE -----------------------

// Storage account for data export (archival)
resource storageAccount 'Microsoft.Storage/storageAccounts@2021-08-01' = {
  name: '${prefix}compliancesa'
  location: location
  tags: tags
  kind: 'StorageV2'
  sku: {
    name: 'Standard_GRS' // Geo-redundant storage for regulatory compliance
  }
  properties: {
    accessTier: 'Cool'
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    allowSharedKeyAccess: true
    networkAcls: {
      bypass: 'AzureServices'
      defaultAction: 'Deny'
      virtualNetworkRules: []
      ipRules: []
    }
    encryption: {
      services: {
        blob: {
          enabled: true
        }
        file: {
          enabled: true
        }
      }
      keySource: 'Microsoft.Storage'
    }
  }
}

// Data Export for long-term storage in Azure Data Lake (for GDPR/CCPA/SOX compliance)
resource sentinelDataExport 'Microsoft.OperationalInsights/workspaces/dataExports@2020-08-01' = {
  name: '${sentinelWorkspaceName}/compliance-data-export'
  properties: {
    destination: {
      resourceId: storageAccount.id
    }
    tableName: 'SecurityEvent'
    enabled: true
  }
}

// Add GDPR/CCPA compliance lock to prevent accidental deletion
resource deleteLock 'Microsoft.Authorization/locks@2020-05-01' = {
  name: '${prefix}-compliance-delete-lock'
  properties: {
    level: 'CanNotDelete'
    notes: 'This lock prevents deletion of resources required for regulatory compliance (SOX, GDPR, CCPA)'
  }
  scope: storageAccount
}

// Output storage account ID for reference
output storageAccountId string = storageAccount.id
output dataExportName string = 'compliance-data-export'
