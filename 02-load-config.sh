#!/usr/bin/env bash

set -euf -o pipefail

# Create backup of existing config & copy new config to container
timestamp=$(date +%Y-%m-%d_%H:%M:%S)

echo "🔧 Create \"config/\" directory if it does not exist.."
docker exec -u root distributey sh -c "[ ! -d /opt/distributey/config/ ] && mkdir -p /opt/distributey/config/init || echo \"(Config directory already exists)\""

echo "🗑️ Delete current config.."
docker exec -u root distributey sh -c "rm -rf /opt/distributey/config/*"

echo "💾 Copy new config.."
docker cp config/. distributey:/opt/distributey/config/

echo "🔧 Set file permissions.."
docker exec -u root distributey chown -R 0:0 /opt/distributey/config
docker exec -u root distributey find /opt/distributey/config/ -type d -exec chmod o+rx {} \;
docker exec -u root distributey find /opt/distributey/config/ -type f -exec chmod o+r {} \;
