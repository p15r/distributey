#!/usr/bin/env bash

set -euf -o pipefail

echo "🔧 Set file permissions.."
find config/ -type d -exec chmod o=rx {} \;
find config/ -type f -exec chmod o=r {} \;
