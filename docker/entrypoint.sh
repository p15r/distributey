#!/usr/bin/env sh

# set
# -e            exit on error
# -u            treat unset variables as an error
# -f            disable filename expansion (globbing)
# -o pipefail   the return value of a pipeline is the value of the last (rightmost)
#                   command to exit with a non-zero status

set -euf -o pipefail

gunicorn --workers 5 \
    --bind 0.0.0.0:5000 \
    --access-logfile - \
    --error-logfile - \
    --reload --reload-extra-file /opt/hyok-wrapper \
    wsgi:app
