#!/usr/bin/env bash

# set
# -e            exit on error
# -u            treat unset variables as an error
# -f            disable filename expansion (globbing)
# -o pipefail   the return value of a pipeline is the value of the last (rightmost)
#                   command to exit with a non-zero status

set -euf -o pipefail

# Workaround: make nginx config accessible in container
chmod o+r docker/nginx.conf

echo '💾 Downloading Terraform providers...'
# change URLs to custom provider mirrors if required
tr_provider_url_vault="https://releases.hashicorp.com/terraform-provider-vault/2.13.0/terraform-provider-vault_2.13.0_linux_amd64.zip"
tr_provider_url_null="https://releases.hashicorp.com/terraform-provider-null/2.1.2/terraform-provider-null_2.1.2_linux_amd64.zip"

curl --progress-bar -L -o terraform-provider-vault_2.13.0_linux_amd64.zip $tr_provider_url_vault
curl --progress-bar -L -o terraform-provider-null_2.1.2_linux_amd64.zip $tr_provider_url_null

echo "🛫 Starting containers..."
cd docker
docker-compose up -d
cd ..

echo '🔧 Installing Terraform providers...'
unzip -q -o terraform-provider-vault_2.13.0_linux_amd64.zip -d terraform_tmp
unzip -q -o terraform-provider-null_2.1.2_linux_amd64.zip -d terraform_tmp
# $(id -u)/$(id -g) because this path is mounted from a local directory into the container (terraform runs w/ root anyway)
docker exec -u $(id -u):$(id -g) terraform mkdir -p /terraform/.terraform/plugins/registry.terraform.io/hashicorp/vault/2.13.0/linux_amd64/
docker exec -u $(id -u):$(id -g) terraform mkdir -p /terraform/.terraform/plugins/registry.terraform.io/hashicorp/null/2.1.2/linux_amd64/
docker cp terraform_tmp/terraform-provider-vault_v2.13.0_x4 terraform:/terraform/.terraform/plugins/registry.terraform.io/hashicorp/vault/2.13.0/linux_amd64/terraform-provider-vault_v2.13.0_x4
docker cp terraform_tmp/terraform-provider-null_v2.1.2_x4 terraform:/terraform/.terraform/plugins/registry.terraform.io/hashicorp/null/2.1.2/linux_amd64/terraform-provider-null_v2.1.2_x4
echo 'ℹ️  Terraform providers installed.'

# Cleanup
echo '🧹 Removing cached files..'
rm terraform-provider-vault_2.13.0_linux_amd64.zip terraform-provider-null_2.1.2_linux_amd64.zip
rm -r terraform_tmp

# Manually provision Vault like:
# sleep 2 # give Vault time to start
# echo 'Configuring Vault..'
# Enable dynamic secrets:
# docker exec vault vault secrets enable transit
# Create Salesforce secret & mark it exportable:
# docker exec vault vault write transit/keys/salesforce exportable=true
# Verify: `docker exec vault vault read transit/keys/salesforce`

echo "ℹ️  Container processes:"
docker ps -a
