#!/usr/bin/env bash

# set
# -e            exit on error
# -u            treat unset variables as an error
# -f            disable filename expansion (globbing)
# -o pipefail   the return value of a pipeline is the value of the last (rightmost)
#                   command to exit with a non-zero status

set -euf -o pipefail

#cert_dir="docker/certs"
#if [ ! -d "$cert_dir" ]; then
#    mkdir $cert_dir
    # make it accessible for gunicorn
#    chmod o+rx $cert_dir
#fi

# Create self-signed cert for testing:
# openssl req -x509 -nodes -days 999 -newkey rsa:2048 -keyout docker/certs/nginx.key -out docker/certs/nginx.crt -subj "/C=No/ST=NoState/L=NoLocation/O=NoOrg/OU=NoOrgUnit/CN=NoCommonName"

echo "⛏️  Building container images..."
docker-compose build #--no-cache

echo "🔑 Generate PEM formatted keypair for JWT-based auth for developers..."
[ ! -d "dev/tmp/" ] && mkdir dev/tmp/
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout dev/tmp/jwt.key -out dev/tmp/jwt.pem -subj "/C=No/ST=NoState/L=NoLocation/O=NoOrg/OU=NoOrgUnit/CN=NoCommonName/emailAddress=NoEmailAddress"
openssl x509 -pubkey -noout -in dev/tmp/jwt.pem > dev/tmp/jwt.pub

# Hack: add pubkey to tfvars. Terraform should read pubkey file.
echo "ℹ️  For developers: Add JWT to Terraform config: \"python3 dev/write_jwt_to_tfvars.py\"."
echo "ℹ️  For developers: Copy \"dev/example-config.json\" to \"config/config.json\"."
echo "ℹ️  For developers: Copy \"dev/tmp/jwt.pub\" to \"config/auth/jwt_salesforce_serviceX.pub\"."
