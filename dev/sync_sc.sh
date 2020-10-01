#!/usr/bin/env bash

set -euf -o pipefail

docker cp hyok-wrapper hyok-wrapper:/opt/
docker exec -u root hyok-wrapper chown -R hyok:hyok /opt/hyok-wrapper
