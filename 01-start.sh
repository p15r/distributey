#!/usr/bin/env bash

# set
# -e            exit on error
# -u            treat unset variables as an error
# -f            disable filename expansion (globbing)
# -o pipefail   the return value of a pipeline is the value of the last (rightmost)
#                   command to exit with a non-zero status

set -euf -o pipefail

# Workaround: make nginx config & TLS files accessible in container
chmod o+x docker/certs/
chmod -R o+r docker/nginx.conf docker/certs/

echo '💾 Downloading Terraform providers...'

# if this URL is configured, terraform will not try to download providers from internet
# tf_provider_url_mirror_zip="https://my-mirror.net/tf-cache.zip"

if [ -z ${tf_provider_url_mirror_zip+x} ]; then
    echo 'ℹ️  Attempting to download providers from internet...';
    cd docker/terraform && terraform providers mirror tf-cache && cd ../../
else
    echo "ℹ️  Fetching terraform providers from '$tf_provider_url_mirror_zip'...";
    terraform_zip='tf-cache.zip'
    curl --progress-bar -L -o $terraform_zip $tf_provider_url_mirror_zip
    unzip -q -o $terraform_zip

    echo '🔧 Installing Terraform providers...'
    mv tf-cache docker/terraform

    rm $terraform_zip
fi

echo '🛫 Starting containers...'
cd docker
docker-compose up -d
cd ..

# Cleanup
echo '🧹 Removing locally cached files..'
# TODO: this is a bug! It removes the cache before docker containers started, thus removes the providers cache too early!
#rm -r docker/terraform/tf-cache

# Manually provision Vault like:
# sleep 2 # give Vault time to start
# Enable dynamic secrets:
# docker exec vault vault secrets enable transit
# Create Salesforce secret & mark it exportable:
# docker exec vault vault write transit/keys/salesforce exportable=true
# Verify: `docker exec vault vault read transit/keys/salesforce`

echo 'ℹ️  Container processes:'
docker ps -a
