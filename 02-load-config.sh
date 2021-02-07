#!/usr/bin/env bash

set -euf -o pipefail

# Create backup of existing config & copy new config to container
timestamp=$(date +%Y-%m-%d_%H:%M:%S)

echo "🔧 Create \"config/\" directory if it does not exist.."
docker exec -u root distributey sh -c "[ ! -d /opt/distributey/config/active ] && mkdir -p /opt/distributey/config/active/init || echo \"(Config directory already exists)\""

echo "💾 Create backup of current config.."
docker exec -u root distributey sh -c "mkdir /opt/distributey/config/config-$timestamp && cp -r /opt/distributey/config/active/* /opt/distributey/config/config-$timestamp"

echo "🗑️ Delete current config.."
docker exec -u root distributey sh -c "rm -rf /opt/distributey/config/active/*"

echo "💾 Copy new config.."
docker cp config/. distributey:/opt/distributey/config/active/

echo "🔧 Set file permissions.."
docker exec -u root distributey chown -R distributey:distributey /opt/distributey/config/active

# gunicorn reloads only if a python file changes..
#touch distributey/app.py
#docker cp distributey/app.py distributey:/opt/distributey/app.py
#docker exec -u root distributey chown -R distributey:distributey /opt/distributey/app.py
