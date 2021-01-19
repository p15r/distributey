#!/usr/bin/env bash

set -euf -o pipefail

echo "🛑 Removing containers..."
cd docker
docker-compose down
cd ..

echo '🧹 Removing locally cached files..'
[ -d docker/terraform/tf-cache ] && rm -r docker/terraform/tf-cache
[ -f docker/terraform/.terraform.lock.hcl ] && rm docker/terraform/.terraform.lock.hcl

echo '🔓 Resetting ownership of Vault config bind mount'
sudo chown -R $USER: ./docker/vault

echo '🔥 Remove old Vault TLS files from dev setup'
rm docker/vault/{myCA.crt,vault_combined.pem,vault.key}
