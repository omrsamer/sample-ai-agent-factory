# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""AWS Lambda entry point of the approver function (API Gateway HTTP API, payload v2).

Serves only the approver routes and only when PORTAL_ACTION_ROLE is "approver".
"""

from mangum import Mangum

from portal_api.actions.app import create_action_app

app = create_action_app("approver")
handler = Mangum(app, lifespan="off")
