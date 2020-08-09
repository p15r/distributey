#!/usr/bin/env bash

# set
# -e            exit on error
# -u            treat unset variables as an error
# -f            disable filename expansion (globbing)
# -o pipefail   the return value of a pipeline is the value of the last (rightmost)
#                   command to exit with a non-zero status

set -euf -o pipefail

output_dir="output"
if [ ! -d "$output_dir" ]; then
    mkdir $output_dir
fi

docker create --name hyok-wrapper \
    -p 0.0.0.0:443:443/tcp \
    -v "$(pwd)"/output:/opt/hyok-wrapper/output \
    pat/hyok-wrapper:0.1

docker start hyok-wrapper
