# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""How long a change to a Runtime's resource policy takes to apply everywhere.

The service applies a policy change host by host, and the two directions
differ. Both figures were measured on a live Runtime under steady calls and
are rounded up:

- after the deny statement was written, an occasional invocation still
  succeeded for up to 52 seconds (39 in a second run), and none after that;
- after it was removed, a large share of calls was still refused for the
  first minutes and the last refusal came 263 and 269 seconds later in two
  runs, with none in the seven minutes that followed.

So a contained agent is closed within about 90 seconds, and a released agent
can keep refusing some calls for about five minutes. Every response and the user
interface say so instead of "now".
"""

from __future__ import annotations

CONTAIN_DELAY_SECONDS = 90
RELEASE_DELAY_SECONDS = 300


def delay_words(seconds: int) -> str:
    """A delay in words: "about 90 seconds" below two minutes, "about 5 minutes" from there on."""
    if seconds < 120:
        return f"about {seconds} seconds"
    return f"about {round(seconds / 60)} minutes"
