#!/usr/bin/env bash

set -euf -o pipefail

echo '🛬 Stopping distributey...'
cd docker
docker-compose stop
cd ..

echo '🔓 Resetting ownership of Vault config bind mount'
sudo chown -R $USER: ./docker/vault