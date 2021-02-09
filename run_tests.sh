#!/usr/bin/env bash

set -euf -o pipefail

# check if var exists using expansion
if [[ ${PYTHONPATH:+1} ]]; then
    export PYTHONPATH=${PYTHONPATH}:"distributey"/
else
    export PYTHONPATH="distributey"/
fi

function help {
    echo -e "-h\tShow help."
    echo -e "-u\tRun unit tests."
    echo -e "-i\tRun integration tests."
    echo -e "-a\tRun unit & integration tests."
    exit 0
}

function runtests {
    export DY_CFG_PATH='config/config.json'
    python3 -m coverage run -m pytest -s -vv $1
    python3 -m coverage report -m $(find distributey/ -name "*.py")
    python3 -m coverage xml $(find distributey/ -name "*.py")
}

function unittest {
    echo 'Running unit tests & creating coverage report...'
    runtests "tests/unit/"
}

function integrationtest {
    echo 'Running integration tests & creating coverage report...'
    runtests "tests/integration/"
}

function alltests {
    echo 'Running all tests & creating coverage report...'
    runtests "tests/"
}

while getopts huia flag
do
    case "${flag}" in
        h) help;;
        u) unittest;;
        i) integrationtest;;
        a) alltests;;
        *) help;;
    esac
done

if [ $OPTIND -eq 1 ]; then help; fi
