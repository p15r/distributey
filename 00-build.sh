#!/usr/bin/env bash

# set
# -e            exit on error
# -u            treat unset variables as an error
# -f            disable filename expansion (globbing)
# -o pipefail   the return value of a pipeline is the value of the last (rightmost)
#                   command to exit with a non-zero status

set -euf -o pipefail

openssl req -x509 -nodes -days 999 -newkey rsa:2048 -keyout docker/certs/nginx.key -out docker/certs/nginx.crt -subj "/C=SC/ST=SomeRegion/L=Some Valey/O=SomeOrg/OU=SomeOrgUnit/CN=somecommonname"
chmod o+r docker/certs/nginx.key docker/certs/nginx.crt

docker-compose build
