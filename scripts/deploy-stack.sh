#!/bin/bash

set -euo pipefail

DEPLOYMENT_STACK_NAME="private-aks-cluster"

# Log on to Azure
REGION_COUNT=$(az account list-locations --query "length([])")
if [ "$REGION_COUNT" -eq 0 ]; then
    echo "Logging in to Azure CLI..."
    az login --use-device-code
else
    echo "Already logged in to Azure CLI."
fi

# Create deployment stack
echo "Creating deployment stack..."
CURRENT_IP_ADDRESS=$(curl -s ifconfig.me)
# az stack sub create \
#     --action-on-unmanage "detachAll" \
#     --deny-settings-mode none \
#     --location "eastus2" \
#     --name "$DEPLOYMENT_STACK_NAME" \
#     --template-file "./bicep/main.bicep" \
#     --parameters allowedIpAddresses="$CURRENT_IP_ADDRESS" \
#     --yes

# Create app1 Key Vault certificate
DEPLOYMENT_STACK=$(az stack sub show --name "$DEPLOYMENT_STACK_NAME")
KEY_VAULT_NAME=$(echo "$DEPLOYMENT_STACK" | jq -r '.outputs.keyVaultName.value')
APP1_KEY_VAULT_CERTIFICATE_NAME="app1-certificate"

# If the certificate already exists, get its url; otherwise, create it.az
APP1_KEY_VAULT_CERTIFICATE_URL=$(az keyvault certificate list \
                                    --vault-name "$KEY_VAULT_NAME" \
                                    --query "[?name=='$APP1_KEY_VAULT_CERTIFICATE_NAME'].name" \
                                    --output tsv)
if [[ -z "$APP1_KEY_VAULT_CERTIFICATE_URL" ]]; then
    echo "Creating app1 Key Vault certificate..."
    APP1_KEY_VAULT_CERTIFICATE_URL=$(az keyvault certificate create \
                                        --vault-name "$KEY_VAULT_NAME" \
                                        --name "$APP1_KEY_VAULT_CERTIFICATE_NAME" \
                                        --policy "$(az keyvault certificate get-default-policy)" \
                                        --query "target" \
                                        --output tsv)
fi

echo "Deploying Helm chart..."
AKS_CLUSTER_NAME=$(echo "$DEPLOYMENT_STACK" | jq -r '.outputs.aksClusterName.value')
AKS_NAMESPACE_NAME=$(echo "$DEPLOYMENT_STACK" | jq -r '.outputs.app1AksNamespaceName.value')
DNS_ZONE_NAME=$(echo "$DEPLOYMENT_STACK" | jq -r '.outputs.dnsZoneName.value')
KEY_VAULT_STORAGE_ACCOUNT_CONNECTION_STRING_SECRET_NAME=$(echo "$DEPLOYMENT_STACK" | jq -r '.outputs.keyVaultStorageAccountConnectionStringSecretName.value')
MANAGED_IDENTITY_CLIENT_ID=$(echo "$DEPLOYMENT_STACK" | jq -r '.outputs.app1ManagedIdentityClientId.value')
RESOURCE_GROUP_NAME=$(echo "$DEPLOYMENT_STACK" | jq -r '.outputs.resourceGroupName.value')
SERVICE_ACCOUNT_NAME=$(echo "$DEPLOYMENT_STACK" | jq -r '.outputs.app1ServiceAccountName.value')
TENANT_ID=$(az account show --query "tenantId" --output tsv)
HELM_COMMAND="helm upgrade \"app1\" . \\
                --install \\
                --atomic \\
                --namespace \"$AKS_NAMESPACE_NAME\" \\
                --create-namespace \\
                --set dnsZoneName=\"$DNS_ZONE_NAME\" \\
                --set keyVaultName=\"$KEY_VAULT_NAME\" \\
                --set keyVaultCertificateUrl=\"$APP1_KEY_VAULT_CERTIFICATE_URL\" \\
                --set keyVaultSecretProviderName=\"app1-keyvault-secret-provider\" \\
                --set keyVaultStorageAccountConnectionStringSecretName=\"$KEY_VAULT_STORAGE_ACCOUNT_CONNECTION_STRING_SECRET_NAME\" \\
                --set managedIdentityClientId=\"$MANAGED_IDENTITY_CLIENT_ID\" \\
                --set serviceAccountName=\"$SERVICE_ACCOUNT_NAME\" \\
                --set tenantId=\"$TENANT_ID\""
cd "./helm/app1/"
az aks command invoke \
    --resource-group "$RESOURCE_GROUP_NAME" \
    --name "$AKS_CLUSTER_NAME" \
    --file . \
    --command "$HELM_COMMAND"