#!/usr/bin/env bash

set -o pipefail
set -o errexit

err_report() {
    echo "Error on line $(caller)" >&2
    awk 'NR>L-4 && NR<L+4 { printf "%-5d%3s%s\n",NR,(NR==L?">>>":""),$0 }' L=$1 $0
}

trap 'err_report $LINENO' ERR

# check if terraform is installed
terraform version > /dev/null

# Make nginx config & TLS files accessible in container
chmod o+x docker/certs/
chmod -R o+r docker/nginx.conf docker/certs/

arch=$(uname -i)

if [ "$arch" == "aarch64" ]; then
    arch="arm64"
fi

if [ "$arch" == "x86_64" ]; then
    arch="amd64"
fi

echo '💾 Downloading Terraform providers...'

# if this URL is configured, terraform will not try to download providers from internet
# tf_provider_url_mirror_zip="https://my-mirror.net/tf-cache.zip"

if [ -d docker/terraform/tf-cache/ ] ; then
    echo "Providers have already been downloaded."
else
    if [ -z ${tf_provider_url_mirror_zip+x} ]; then
        echo 'ℹ️  Attempting to download providers from internet...';

        cd docker/terraform && terraform providers mirror -platform=linux_"$arch" tf-cache && cd ../../
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
docker-compose --compatibility up -d

echo '🛡️  Setting pid limit (no longer supported via docker-compose v3 format)...'
docker container update --pids-limit=20 distributey
docker container update --pids-limit=20 nginx

echo 'ℹ️  Container processes:'
docker ps
