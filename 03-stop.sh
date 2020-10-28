#!/usr/bin/env bash

set -euf -o pipefail

echo '🛬 Stopping distributey...'
cd docker
docker-compose stop
cd ..
