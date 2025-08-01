#!/bin/bash

cd "$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
set -e -x -u

source ./run-ide-services-base.sh

## make it rebuild oauth2-bro

docker compose -f "$DEMO_DIR/docker-compose.yml" -f "$(pwd)/docker-compose.proxy.override.yaml" config mock-proxy
docker compose -f "$DEMO_DIR/docker-compose.yml" -f "$(pwd)/docker-compose.proxy.override.yaml" config tbe-server


docker compose -f "$DEMO_DIR/docker-compose.yml" -f "$(pwd)/docker-compose.proxy.override.yaml" rm -f mock-proxy
docker compose -f "$DEMO_DIR/docker-compose.yml" -f "$(pwd)/docker-compose.proxy.override.yaml" up --build



