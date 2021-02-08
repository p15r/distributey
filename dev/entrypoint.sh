#!/usr/bin/env bash

set -euf -o pipefail

cd distributey

export FLASK_APP=app
#export FLASK_ENV=development

flask run
