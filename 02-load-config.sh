#!/usr/bin/env bash

set -euf -o pipefail

# Create backup of existing config & copy new config to container
timestamp=$(date +%Y-%m-%d_%H:%M:%S)

echo "🔧 Create \"config/\" directory if it does not exist.."
docker exec distributey sh -c "[ ! -d /opt/distributey/config/ ] && mkdir -p /opt/distributey/config/init || echo \"(Config directory already exists)\""

echo "💾 Create backup of current config.."
docker exec distributey sh -c "mkdir /opt/distributey/config-$timestamp && cp -r /opt/distributey/config/* /opt/distributey/config-$timestamp"

echo "🗑️ Delete current config.."
docker exec -u root distributey sh -c "rm -rf /opt/distributey/config/*"

echo "💾 Copy new config.."
docker cp config/ distributey:/opt/distributey/

echo "🔧 Set file permissions.."
docker exec -u root distributey chown -R distributey:distributey /opt/distributey/config

# gunicorn reloads only if a python file changes..
touch distributey/app.py
docker cp distributey/app.py distributey:/opt/distributey/app.py
docker exec -u root distributey chown -R distributey:distributey /opt/distributey/app.py
