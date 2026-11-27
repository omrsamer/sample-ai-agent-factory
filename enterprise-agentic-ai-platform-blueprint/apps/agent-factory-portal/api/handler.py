# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""AWS Lambda entry point for the Agent Factory Portal API (API Gateway HTTP API, payload v2)."""

from mangum import Mangum

from portal_api.app import create_app

app = create_app()
handler = Mangum(app, lifespan="off")
