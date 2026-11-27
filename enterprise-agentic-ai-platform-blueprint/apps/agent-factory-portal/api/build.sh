#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
# Builds dist/ ready to be zipped as an AWS Lambda package (arm64, Python 3.13).
# boto3/botocore are bundled at the versions pinned in requirements.txt because
# the SDK inside the Lambda runtime can be older than the Agent Registry service.
set -euo pipefail

cd "$(dirname "$0")"
PYTHON="${PYTHON:-python3}"

rm -rf dist
mkdir -p dist

"$PYTHON" -m pip install \
  --platform manylinux2014_aarch64 \
  --implementation cp \
  --python-version 3.13 \
  --only-binary=:all: \
  --target dist \
  --upgrade \
  --quiet \
  -r requirements.txt

cp -R portal_api dist/portal_api
cp handler.py registrar_handler.py approver_handler.py dist/
mkdir -p dist/schemas
cp schemas/*.json dist/schemas/

find dist -type d -name "__pycache__" -prune -exec rm -rf {} +
find dist -type d -name "tests" -path "*/site-packages/*" -prune -exec rm -rf {} + 2>/dev/null || true
rm -rf dist/bin

echo "Built $(pwd)/dist"
