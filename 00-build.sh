#!/usr/bin/env bash

set -euf -o pipefail

# Create self-signed cert for development purposes:
# openssl req -x509 -nodes -days 999 -newkey rsa:2048 -keyout docker/certs/nginx.key -out docker/certs/nginx.crt -subj "/C=No/ST=NoState/L=NoLocation/O=NoOrg/OU=NoOrgUnit/CN=NoCommonName"

echo "⛏️  Building container images..."
docker-compose build

echo "🔑 Generate PEM formatted keypair for JWT-based auth for developers..."
[ ! -d "dev/tmp/" ] && mkdir dev/tmp/
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout dev/tmp/jwt.key -out dev/tmp/jwt.pem -subj "/C=No/ST=NoState/L=NoLocation/O=NoOrg/OU=NoOrgUnit/CN=NoCommonName/emailAddress=NoEmailAddress"
openssl x509 -pubkey -noout -in dev/tmp/jwt.pem > dev/tmp/jwt.pub

# Hack: add pubkey to tfvars. Terraform should read pubkey file.
echo "ℹ️  For developers: Add JWT to Terraform config: \"python3 dev/write_jwt_to_tfvars.py\"."
echo "ℹ️  For developers: Copy \"dev/example-config.json\" to \"config/config.json\"."
echo "ℹ️  For developers: Copy \"dev/tmp/jwt.pub\" to \"config/auth/jwt_salesforce_serviceX.pub\"."
