#!/usr/bin/env bash

set -euf -o pipefail

# Make nginx config & TLS files accessible in container
chmod o+x docker/certs/
chmod -R o+r docker/nginx.conf docker/certs/

echo '💾 Downloading Terraform providers...'

# if this URL is configured, terraform will not try to download providers from internet
# tf_provider_url_mirror_zip="https://my-mirror.net/tf-cache.zip"

if [ -d docker/terraform/tf-cache/ ] ; then
    echo "Providers have already been downloaded."
else
    if [ -z ${tf_provider_url_mirror_zip+x} ]; then
        echo 'ℹ️  Attempting to download providers from internet...';

        cd docker/terraform && terraform providers mirror -platform=linux_amd64 tf-cache && cd ../../
    else
        echo "ℹ️  Fetching terraform providers from '$tf_provider_url_mirror_zip'...";
        terraform_zip='tf-cache.zip'
        curl --progress-bar -L -o $terraform_zip $tf_provider_url_mirror_zip
        unzip -q -o $terraform_zip

        echo '🔧 Installing Terraform providers...'
        mv tf-cache docker/terraform

        rm $terraform_zip
    fi
fi

echo '🛫 Starting containers...'
cd docker
docker-compose up -d
cd ..

echo 'ℹ️  Container processes:'
docker ps -a
