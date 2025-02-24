#!/bin/bash

set -euo pipefail

DEPLOYMENT_STACK_NAME="aks-cluster"

# Log on to Azure
REGION_COUNT=$(az account list-locations --query "length([])" --output tsv 2> /dev/null)
if ! [[ "$REGION_COUNT" =~ ^[0-9]+$ ]] || [ "$REGION_COUNT" -eq 0 ]; then
    echo "Logging in to Azure CLI..."
    az login --use-device-code
else
    echo "Already logged in to Azure CLI."
fi

# Enabling VNET integration preview feature
echo "Enabling VNET integration preview feature..."
az feature register \
    --namespace "Microsoft.ContainerService" \
    --name "EnableAPIServerVnetIntegrationPreview"

FEATURE_SHOW_COMMAND="az feature show \
                        --namespace 'Microsoft.ContainerService' \
                        --name 'EnableAPIServerVnetIntegrationPreview' \
                        --query 'properties.state' \
                        --output tsv"
REGISTRATION_STATUS=$(eval "$FEATURE_SHOW_COMMAND")
MAX_RETRIES=20
RETRY_COUNT=0
while [ "$REGISTRATION_STATUS" != "Registered" ] && [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    echo "Waiting for feature registration to complete... (Attempt: $((RETRY_COUNT+1))/$MAX_RETRIES)"
    sleep 10
    REGISTRATION_STATUS=$(eval "$FEATURE_SHOW_COMMAND")
    RETRY_COUNT=$((RETRY_COUNT+1))
done

if [ "$REGISTRATION_STATUS" != "Registered" ]; then
    echo "Feature registration did not complete within the maximum retry limit."
    exit 1
fi

# Create deployment stack
echo "Creating deployment stack..."
CURRENT_IP_ADDRESS=$(curl -s ifconfig.me)
VIRTUAL_MACHINE_ADMIN_PASSWORD=$(openssl rand -base64 16)
az stack sub create \
    --action-on-unmanage "detachAll" \
    --deny-settings-mode none \
    --location "westus3" \
    --name "$DEPLOYMENT_STACK_NAME" \
    --template-file "./bicep/main.bicep" \
    --parameters allowedIpAddresses="$CURRENT_IP_ADDRESS" \
    --parameters virtualMachineAdminPassword="$VIRTUAL_MACHINE_ADMIN_PASSWORD" \
    --yes

# Create app1 Key Vault certificate
DEPLOYMENT_STACK=$(az stack sub show --name "$DEPLOYMENT_STACK_NAME")
KEY_VAULT_NAME=$(echo "$DEPLOYMENT_STACK" | jq -r '.outputs.keyVaultName.value')
APP1_KEY_VAULT_CERTIFICATE_NAME="app1-certificate"

# If the certificate already exists, get its url; otherwise, create it.az
APP1_KEY_VAULT_CERTIFICATE_URL=$(az keyvault certificate list \
                                    --vault-name "$KEY_VAULT_NAME" \
                                    --query "[?name=='$APP1_KEY_VAULT_CERTIFICATE_NAME'].target" \
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

echo "Deploying common Helm chart..."
HELM_COMMAND="helm upgrade \"common\" . \\
                --install \\
                --atomic \\
                --namespace \"common\" \\
                --create-namespace"
az aks command invoke \
    --resource-group "$RESOURCE_GROUP_NAME" \
    --name "$AKS_CLUSTER_NAME" \
    --file . \
    --command "$HELM_COMMAND"

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