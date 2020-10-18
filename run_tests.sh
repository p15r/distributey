#!/usr/bin/env bash

set -euf -o pipefail

# check if var exists using expansion
if [[ ${PYTHONPATH:+1} ]]; then
    export PYTHONPATH=${PYTHONPATH}:"hyok-wrapper"/
else
    export PYTHONPATH="hyok-wrapper"/
fi

echo 'Running tests & create coverage report...'
coverage run -m pytest -s -vv tests/unit/
coverage report -m
