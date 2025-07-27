#!/bin/bash

cd "$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
set -e -x -u

VERSION=2025.1.2.22
URL=https://download.jetbrains.com/ide-services/demo/tbe-demo-$VERSION.zip
DEMO_ZIP=$(pwd)/tbe-demo-$VERSION.zip
DEMO_DIR=$(pwd)/tbe-demo-$VERSION

if [ ! -f "$DEMO_ZIP" ]; then
  rm -rf "$DEMO_DIR" || true
  curl --fail -L --output "$DEMO_ZIP" "$URL"
fi

if [ ! -d "$DEMO_DIR" ]; then
  rm -rf "$DEMO_DIR" || true
  unzip "$DEMO_ZIP" -d "$DEMO_DIR"

  # Move all files from first-level directories to parent
  find "$DEMO_DIR" -mindepth 2 -maxdepth 2 -type f -exec mv {} "$DEMO_DIR/" \;

  # Remove empty directories
  find "$DEMO_DIR" -mindepth 1 -type d -empty -delete
fi


