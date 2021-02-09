#!/usr/bin/env bash

set -euf -o pipefail

function help {
    echo -e "-h\tShow help."
    echo -e "-d\tEnable developer mode."
    exit 0
}

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
