#!/usr/bin/env bash

set -o pipefail
set -o errexit

err_report() {
    echo "Error on line $(caller)" >&2
    awk 'NR>L-4 && NR<L+4 { printf "%-5d%3s%s\n",NR,(NR==L?">>>":""),$0 }' L=$1 $0
}

trap 'err_report $LINENO' ERR

echo "🛑 Removing containers..."
docker-compose --compatibility down

echo '🧹 Removing locally cached files..'
[ -d docker/terraform/tf-cache ] && rm -r docker/terraform/tf-cache
[ -f docker/terraform/.terraform.lock.hcl ] && rm -f docker/terraform/.terraform.lock.hcl

echo '🔓 Resetting ownership of Vault config bind mount'
sudo chown -R $USER: ./docker/vault

echo '🧹 Remove old Vault TLS files from dev setup'
[ -f docker/vault/myCA.crt ] && sudo rm docker/vault/myCA.crt
[ -f docker/vault/vault_combined.pem ] && sudo rm docker/vault/vault_combined.pem
[ -f docker/vault/vault.key ] && sudo rm docker/vault/vault.key
