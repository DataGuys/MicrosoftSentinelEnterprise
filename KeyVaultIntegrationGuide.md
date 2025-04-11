Key Vault Integration Guide
markdown# Enhanced Key Vault Integration Guide

This guide provides best practices for integrating Azure Key Vault with your Enterprise Sentinel deployment to enhance security.

## Key Vault Configuration

### Implementing Customer-Managed Keys (CMK)

For organizations with stringent security and compliance requirements, implementing Customer-Managed Keys provides enhanced control over encryption keys:

1. Create a dedicated Key Vault for Sentinel encryption keys:

```bash
az keyvault create \
  --name "kv-sentinel-cmk-prod" \
  --resource-group "$RESOURCE_GROUP" \
  --location "$LOCATION" \
  --sku "Premium" \
  --enabled-for-disk-encryption true \
  --enabled-for-template-deployment true

Generate a new RSA key in Key Vault:

bashaz keyvault key create \
  --vault-name "kv-sentinel-cmk-prod" \
  --name "sentinel-encryption-key" \
  --kty "RSA" \
  --size 3072

Configure automated key rotation:

bashaz keyvault key rotation-policy update \
  --vault-name "kv-sentinel-cmk-prod" \
  --name "sentinel-encryption-key" \
  --value @key-rotation-policy.json

Sample key rotation policy (key-rotation-policy.json):

json{
  "lifetimeActions": [
    {
      "trigger": {
        "timeAfterCreate": "P90D"
      },
      "action": {
        "type": "Rotate"
      }
    }
  ],
  "attributes": {
    "expiryTime": "P2Y"
  }
}
