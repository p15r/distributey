#!/usr/bin/env bash

set -o pipefail
set -o errexit

err_report() {
    echo "Error on line $(caller)" >&2
    awk 'NR>L-4 && NR<L+4 { printf "%-5d%3s%s\n",NR,(NR==L?">>>":""),$0 }' L=$1 $0
}

trap 'err_report $LINENO' ERR

echo '🛬 Stopping distributey...'
docker-compose --compatibility stop

echo '🔓 Resetting ownership of Vault config bind mount'
sudo chown -R $USER: ./docker/vault
