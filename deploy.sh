#!/bin/bash
# Enterprise Deployment Script for Multi-Workspace Azure Sentinel Architecture
# This script helps deploy the Bicep template for a tiered Azure Sentinel logging architecture
# with support for Log Analytics Cluster and regulatory compliance (SOX, GDPR, CCPA)

# Set these variables before running
RESOURCE_GROUP="rg-sentinel-enterprise"
LOCATION="eastus"
DEPLOYMENT_NAME="sentinel-enterprise-deployment"
PREFIX="sec"

# Compliance settings (SOX, GDPR, CCPA)
DEFAULT_RETENTION_DAYS=2557  # 7 years for SOX compliance
VERBOSE_RETENTION_DAYS=2557  # 7 years for SOX compliance
STAGING_RETENTION_DAYS=90    # 90 days for staging

# Log Analytics Cluster settings
USE_LA_CLUSTER=true          # Set to true to deploy a Log Analytics Cluster
LA_CLUSTER_CAPACITY_GB=2000  # Capacity reservation in GB/day (for >$500K annual spend)

# Customer-Managed Keys for encryption (for GDPR/CCPA)
ENABLE_CMK=false             # Set to true to use Customer-Managed Keys
KEY_VAULT_ID=""              # Resource ID of your Key Vault
KEY_NAME=""                  # Name of the key in Key Vault
KEY_VERSION=""               # Version of the key

# Login to Azure (uncomment if not already logged in)
# az login

# Create a resource group if it doesn't exist
echo "Creating resource group $RESOURCE_GROUP in $LOCATION if it doesn't exist..."
az group create --name $RESOURCE_GROUP --location $LOCATION

# Check if we need to add VM IDs to the deployment
VM_PARAMS=""
if [ -n "$VM_IDS" ]; then
  VM_IDS_PARAM=$(printf '%s ' "${VM_IDS[@]}" | jq -R -s -c 'split(" ")[:-1]')
  VM_PARAMS="vmResourceIds=$VM_IDS_PARAM"
fi

# Prepare CMK parameters if enabled
CMK_PARAMS=""
if [ "$ENABLE_CMK" = true ]; then
  if [ -z "$KEY_VAULT_ID" ] || [ -z "$KEY_NAME" ] || [ -z "$KEY_VERSION" ]; then
    echo "Error: When enableCustomerManagedKey is true, keyVaultId, keyName, and keyVersion must be provided."
    exit 1
  fi
  CMK_PARAMS="enableCustomerManagedKey=$ENABLE_CMK keyVaultId=$KEY_VAULT_ID keyName=$KEY_NAME keyVersion=$KEY_VERSION"
fi

# Deploy the Bicep template with enterprise settings
echo "Deploying the Enterprise Multi-Workspace Azure Sentinel Architecture..."
az deployment group create \
  --resource-group $RESOURCE_GROUP \
  --template-file main.bicep \
  --parameters \
      prefix=$PREFIX \
      location=$LOCATION \
      defaultRetentionDays=$DEFAULT_RETENTION_DAYS \
      verboseRetentionDays=$VERBOSE_RETENTION_DAYS \
      stagingRetentionDays=$STAGING_RETENTION_DAYS \
      useLogAnalyticsCluster=$USE_LA_CLUSTER \
      laClusterCapacityReservationGB=$LA_CLUSTER_CAPACITY_GB \
      $CMK_PARAMS \
      $VM_PARAMS

echo "Enterprise Sentinel deployment initiated. Check Azure Portal for progress."

# For large environments, this deployment may take 20-30 minutes
echo "Estimated deployment time: 20-30 minutes for full completion"
echo "The Log Analytics Cluster alone can take 15-20 minutes to provision."

# Wait for deployment to complete (optional, can be commented out for very long deployments)
echo "Waiting for deployment to complete..."
az deployment group wait --name $DEPLOYMENT_NAME --resource-group $RESOURCE_GROUP --created

# Post-deployment verification
echo "Deployment completed. Verifying resources..."

# Verify Log Analytics Cluster (if enabled)
if [ "$USE_LA_CLUSTER" = true ]; then
  echo "Verifying Log Analytics Cluster..."
  CLUSTER_NAME="${PREFIX}-la-cluster"
  CLUSTER_STATUS=$(az monitor log-analytics cluster show --name $CLUSTER_NAME --resource-group $RESOURCE_GROUP --query 'properties.provisioningState' -o tsv)
  echo "Log Analytics Cluster status: $CLUSTER_STATUS"
fi

# Verify workspaces
echo "Verifying Log Analytics Workspaces..."
SENTINEL_WS="${PREFIX}-sentinel-ws"
VERBOSE_WS="${PREFIX}-verbose-ws"
STAGING_WS="${PREFIX}-staging-ws"

# Check workspace provisioning state
SENTINEL_WS_STATUS=$(az monitor log-analytics workspace show --workspace-name $SENTINEL_WS --resource-group $RESOURCE_GROUP --query 'provisioningState' -o tsv)
echo "Sentinel workspace status: $SENTINEL_WS_STATUS"

# Check if Sentinel is enabled
SENTINEL_ENABLED=$(az monitor log-analytics workspace sentinel show --workspace-name $SENTINEL_WS --resource-group $RESOURCE_GROUP --query 'properties.provisioningState' -o tsv 2>/dev/null)
if [ -n "$SENTINEL_ENABLED" ]; then
  echo "Microsoft Sentinel is enabled on the workspace."
else
  echo "Warning: Microsoft Sentinel may not be fully provisioned yet. Please check in the Azure Portal."
fi

# Check Data Export (for compliance)
EXPORT_STATUS=$(az monitor log-analytics workspace data-export list --workspace-name $SENTINEL_WS --resource-group $RESOURCE_GROUP --query '[0].properties.enabled' -o tsv 2>/dev/null)
if [ "$EXPORT_STATUS" = "true" ]; then
  echo "Compliance data export is enabled."
else
  echo "Warning: Compliance data export may not be fully provisioned yet. Please check in the Azure Portal."
fi

# Basic DCR verification
echo "Checking Data Collection Rules..."
DCR_COUNT=$(az monitor data-collection rule list --resource-group $RESOURCE_GROUP --query 'length(@)' -o tsv)
echo "Number of Data Collection Rules deployed: $DCR_COUNT"

echo "Enterprise Sentinel deployment and verification complete."
echo ""
echo "Next steps:"
echo "1. Configure additional data connectors in the Azure Portal"
echo "2. Enable analytics rules in Microsoft Sentinel"
echo "3. Set up data masking for PII (for GDPR/CCPA compliance)"
echo "4. Implement RBAC with segregation of duties (for SOX compliance)"
echo "5. Configure workspace-level customer-managed keys if required"

# Compliance reminder
echo ""
echo "IMPORTANT COMPLIANCE REMINDER:"
echo "This deployment includes features for SOX, GDPR, and CCPA compliance, but additional"
echo "configuration may be necessary to meet all requirements. Please consult with your"
echo "compliance team to ensure all controls are properly implemented."
