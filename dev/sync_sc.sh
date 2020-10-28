#!/usr/bin/env bash

set -euf -o pipefail

docker cp distributey distributey:/opt/
docker exec -u root distributey chown -R distributey:distributey /opt/distributey
