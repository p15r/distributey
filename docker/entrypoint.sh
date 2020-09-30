#!/usr/bin/env sh

set -euf -o pipefail

gunicorn --workers 5 \
    --bind 0.0.0.0:5000 \
    --access-logfile - \
    --error-logfile - \
    --reload --reload-extra-file /opt/hyok-wrapper \
    wsgi:app
