#!/usr/bin/env bash

# set
# -e            exit on error
# -u            treat unset variables as an error
# -f            disable filename expansion (globbing)
# -o pipefail   the return value of a pipeline is the value of the last (rightmost)
#                   command to exit with a non-zero status

set -euf -o pipefail

docker cp hyok-wrapper hyok-wrapper:/opt/
docker exec -u root hyok-wrapper chown -R hyok:hyok /opt/hyok-wrapper
