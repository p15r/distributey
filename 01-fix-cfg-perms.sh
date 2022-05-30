#!/usr/bin/env bash

set -o pipefail
set -o errexit

err_report() {
    echo "Error on line $(caller)" >&2
    awk 'NR>L-4 && NR<L+4 { printf "%-5d%3s%s\n",NR,(NR==L?">>>":""),$0 }' L=$1 $0
}

trap 'err_report $LINENO' ERR



echo "🔧 Set file permissions.."
find config/ -type d -exec chmod o=rx {} \;
find config/ -type f -exec chmod o=r {} \;
