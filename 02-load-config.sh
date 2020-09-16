#!/usr/bin/env bash

# set
# -e            exit on error
# -u            treat unset variables as an error
# -f            disable filename expansion (globbing)
# -o pipefail   the return value of a pipeline is the value of the last (rightmost)
#                   command to exit with a non-zero status

set -euf -o pipefail


# Create backup of existing config & copy new config to container
timestamp=$(date +%Y-%m-%d_%H:%M:%S)

echo "🔧 Create \"config/\" directory if it does not exist.."
docker exec hyok-wrapper sh -c "[ ! -d /opt/hyok-wrapper/config/ ] && mkdir -p /opt/hyok-wrapper/config/init || echo \"(Config directory already exists)\""

echo "💾 Create backup of current config.."
docker exec hyok-wrapper sh -c "mkdir /opt/hyok-wrapper/config-$timestamp && cp -r /opt/hyok-wrapper/config/* /opt/hyok-wrapper/config-$timestamp"

echo "🗑️ Delete current config.."
docker exec -u root hyok-wrapper sh -c "rm -rf /opt/hyok-wrapper/config/*"

echo "💾 Copy new config.."
docker cp config/ hyok-wrapper:/opt/hyok-wrapper/

echo "🔧 Set file permissions.."
docker exec -u root hyok-wrapper chown -R hyok:hyok /opt/hyok-wrapper/config

# gunicorn only reloads if a python file changes..
touch hyok-wrapper/app.py
docker cp hyok-wrapper/app.py hyok-wrapper:/opt/hyok-wrapper/app.py
docker exec -u root hyok-wrapper chown -R hyok:hyok /opt/hyok-wrapper/app.py
