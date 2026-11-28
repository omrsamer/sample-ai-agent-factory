# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""AWS Lambda entry point of the sweeper function (background sweeps of a contained Runtime).

It is invoked by its queue, serves no route, and runs under the containment
function's role. ``PORTAL_ACTION_ROLE`` must be ``sweeper``.
"""

import logging
import os

from portal_api.actions.sweeper import lambda_handler

logging.getLogger().setLevel(os.environ.get("PORTAL_LOG_LEVEL", "INFO"))

handler = lambda_handler
