#!/bin/bash

set -euo pipefail

az stack sub create \
    --action-on-unmanage "detachAll" \
    --deny-settings-mode none \
    --location "eastus2" \
    --name "private-aks-cluster" \
    --template-file "./bicep/main.bicep" \
    --yes