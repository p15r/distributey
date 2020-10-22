#!/usr/bin/env bash

set -euf -o pipefail

# check if var exists using expansion
if [[ ${PYTHONPATH:+1} ]]; then
    export PYTHONPATH=${PYTHONPATH}:"hyok-wrapper"/
else
    export PYTHONPATH="hyok-wrapper"/
fi

function help {
    echo -e "-h\tShow help."
    echo -e "-u\tRun unit tests."
    echo -e "-i\tRun integration tests."
    exit 0
}

function unittest {
    echo 'Running tests & creating coverage report...'
    python3 -m coverage run -m pytest -s -vv tests/unit/
    python3 -m coverage report -m $(find hyok-wrapper/ -name "*.py")
}

function integrationtest {
    echo 'Running tests & creating coverage report...'
    coverage run -m pytest -s -vv tests/integration/
    coverage report -m $(find hyok-wrapper/ -name "*.py")
}

while getopts hui flag
do
    case "${flag}" in
        h) help;;
        u) unittest;;
        i) integrationtest;;
        *) help;;
    esac
done

if [ $OPTIND -eq 1 ]; then help; fi
