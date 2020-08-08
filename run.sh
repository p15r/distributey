#!/usr/bin/env bash

mkdir output

docker run --name hyok-wrapper \
    -p 127.0.0.1:443:443/tcp \
    -v "$(pwd)"/output:/opt/hyok-wrapper/output \
    pat/hyok-wrapper:0.1
