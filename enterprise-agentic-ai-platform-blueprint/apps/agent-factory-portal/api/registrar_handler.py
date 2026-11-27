# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""AWS Lambda entry point of the registrar function (API Gateway HTTP API, payload v2).

Serves only the registrar routes and only when PORTAL_ACTION_ROLE is "registrar".
"""

from mangum import Mangum

from portal_api.actions.app import create_action_app

app = create_action_app("registrar")
handler = Mangum(app, lifespan="off")
