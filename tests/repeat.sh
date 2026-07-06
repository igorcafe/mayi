#!/usr/bin/env bash

set -euo pipefail

times=$1
shift
for i in $(seq 1 $times)
do
    eval "$@"
done
