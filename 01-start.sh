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

cd docker
docker-compose up -d
cd ..

sleep 2 # give Vault time to start

echo 'Configuring Vault..'

# Enable dynamic secrets:
docker exec vault vault secrets enable transit

# Create Salesforce secret & mark it exportable:
docker exec vault vault write transit/keys/salesforce exportable=true

# Verify: `docker exec vault vault read transit/keys/salesforce`
