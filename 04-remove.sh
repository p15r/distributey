#!/usr/bin/env bash

set -euf -o pipefail

echo "🛑 Removing containers..."
docker-compose down

echo '🧹 Removing locally cached files..'
[ -d docker/terraform/tf-cache ] && rm -r docker/terraform/tf-cache
[ -f docker/terraform/.terraform.lock.hcl ] && rm docker/terraform/.terraform.lock.hcl

echo '🔓 Resetting ownership of Vault config bind mount'
sudo chown -R $USER: ./docker/vault

echo '🧹 Remove old Vault TLS files from dev setup'
[ -f docker/vault/myCA.crt ] && sudo rm docker/vault/myCA.crt
[ -f docker/vault/vault_combined.pem ] && sudo rm docker/vault/vault_combined.pem
[ -f docker/vault/vault.key ] && sudo rm docker/vault/vault.key
