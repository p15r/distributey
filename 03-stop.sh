#!/usr/bin/env bash

set -euf -o pipefail

echo '🛬 Stopping distributey...'
docker-compose --compatibility stop

echo '🔓 Resetting ownership of Vault config bind mount'
sudo chown -R $USER: ./docker/vault
