#!/usr/bin/env bash

set -o pipefail
set -o errexit

err_report() {
    echo "Error on line $(caller)" >&2
    awk 'NR>L-4 && NR<L+4 { printf "%-5d%3s%s\n",NR,(NR==L?">>>":""),$0 }' L=$1 $0
}

trap 'err_report $LINENO' ERR

function help {
    echo -e "-h\tShow help."
    echo -e "-d\tEnable developer mode."
    exit 0
}

# check if docker is running
docker ps > /dev/null

dev_mode=false

while getopts hd flag
do
    case "${flag}" in
        h) help;;
        d) dev_mode=true;;
    esac
done


echo "⛏️  Building container images..."
docker-compose --compatibility build

if [ "$dev_mode" = true ] ; then
    ./dev/dev_setup.sh
fi
