#!/usr/bin/env bash

set -euf -o pipefail

echo "⛏️  Building container images..."
docker-compose build

echo "🔑 Dev Note: Generate PEM formatted keypair for JWT-based auth for developers..."
[ ! -d "dev/tmp/" ] && mkdir dev/tmp/
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout dev/tmp/jwt.key -out dev/tmp/jwt.pem -subj "/C=No/ST=NoState/L=NoLocation/O=NoOrg/OU=NoOrgUnit/CN=NoCommonName/emailAddress=NoEmailAddress"
openssl x509 -pubkey -noout -in dev/tmp/jwt.pem > dev/tmp/jwt.pub

echo "🔑 Dev Note: Generate PEM formatted keypair for API hosting..."
openssl req -x509 -nodes -days 999 -newkey rsa:2048 -keyout dev/tmp/nginx.key -out dev/tmp/nginx.crt -subj "/C=No/ST=NoState/L=NoLocation/O=NoOrg/OU=NoOrgUnit/CN=NoCommonName"

echo "🔑 Dev Note: Generate PEM formatted key consumer key..."
openssl req -x509 -nodes -days 999 -newkey rsa:2048 -keyout dev/tmp/key_consumer_key.key -out dev/tmp/key_consumer_key.crt -subj "/C=No/ST=NoState/L=NoLocation/O=NoOrg/OU=NoOrgUnit/CN=NoCommonName"

# Hack: add pubkey to tfvars. Terraform should read pubkey file.
echo 'ℹ️  Dev Note: Add JWT to Terraform config: python3 dev/write_jwt_to_tfvars.py'
echo 'ℹ️  Dev Note: Copy config: cp dev/example-config.json config/config.json'
echo 'ℹ️  Dev Note: Copy JWT public key: cp dev/tmp/jwt.pub config/auth/jwt_salesforce_serviceX.pub'
echo 'ℹ️  Dev Note: Copy self-signed certs for API: cp dev/tmp/nginx.* docker/certs/'
echo 'ℹ️  Dev Note: Copy key consumer key: cp dev/tmp/key_consumer_key.crt config/backend/sfhyok_allservices_key_consumer.crt'
