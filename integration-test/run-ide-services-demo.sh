#!/bin/bash

cd "$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
set -e -x -u

source ./run-ide-services-base.sh

## make it rebuild oauth2-bro
docker compose -f "$DEMO_DIR/docker-compose.yml" -f "$(pwd)/docker-compose.override.yaml" rm -f mock-auth

docker compose -f "$DEMO_DIR/docker-compose.yml" -f "$(pwd)/docker-compose.override.yaml" up --build



