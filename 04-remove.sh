#!/usr/bin/env bash

set -euf -o pipefail

echo "🛑 Removing containers..."
cd docker
docker-compose down
cd ..

echo '🧹 Removing locally cached files..'
rm -r docker/terraform/tf-cache
rm docker/terraform/.terraform.lock.hcl
