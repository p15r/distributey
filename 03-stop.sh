#!/usr/bin/env bash

set -euf -o pipefail

echo '🛬 Stopping HYOK Wrapper...'
cd docker
docker-compose stop
cd ..
