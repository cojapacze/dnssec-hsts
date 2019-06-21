#!/bin/bash -ex
git rev-parse && cd "$(git rev-parse --show-toplevel)"

npm install
./test.sh
