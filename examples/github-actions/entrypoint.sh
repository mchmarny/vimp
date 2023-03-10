#!/bin/bash

set -euo pipefail

project=$1
digest=$2
format=$3

./vulctl import --project cloudy-labz \
                --source $digest \
                --file report.json \
                --format $format
