#!/usr/bin/env bash

# set
# -e            exit on error
# -u            treat unset variables as an error
# -f            disable filename expansion (globbing)
# -o pipefail   the return value of a pipeline is the value of the last (rightmost)
#                   command to exit with a non-zero status

set -euf -o pipefail

# gunicorn only reloads if a python file changes..
touch hyok-wrapper/app.py
docker cp hyok-wrapper/app.py hyok-wrapper:/opt/hyok-wrapper/app.py
docker exec -u root hyok-wrapper chown -R hyok:hyok /opt/hyok-wrapper/app.py

docker cp config/ hyok-wrapper:/opt/hyok-wrapper
docker exec -u root hyok-wrapper chown -R hyok:hyok /opt/hyok-wrapper/config
