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

# Background sweeps after a contain, counted from the end of the request (its messages are sent last).
# The first runs at once, and only when the sweep inside the request left something undone. The
# second comes after every host applies the deny (so it must be later than CONTAIN_DELAY_SECONDS)
# and catches a session that started on a host that had not applied it yet. The third is as late
# as a queue message can be delayed, for a session that wrote its first output late.
FIRST_SWEEP_DELAY_SECONDS = 0
SECOND_SWEEP_DELAY_SECONDS = 120
THIRD_SWEEP_DELAY_SECONDS = 900
SWEEP_DELAYS_SECONDS = (FIRST_SWEEP_DELAY_SECONDS, SECOND_SWEEP_DELAY_SECONDS, THIRD_SWEEP_DELAY_SECONDS)
# The sweeper runs a sweep no earlier than this before the moment it is due. That moment is the
# time of the contain's oldest event in the history plus the sweep's delay. A message from the
# queue is never early: the contain sends its messages after writing its intent, and the queue
# holds each one back for its delay. One that is early was sent some other way, and running it
# would use up a later sweep before the sessions it is there to catch can have started.
# The allowance is for the one case in which the moment is counted from the contain's result
# instead (its intent was not read): a result is written after the messages are sent, by less
# than the containment function's 29 seconds. With it the second sweep still runs no sooner than
# CONTAIN_DELAY_SECONDS after the contain began.
SWEEP_EARLY_TOLERANCE_SECONDS = 30

# The most sessions a background sweep stops per second. Stops count against the cell account's
# data-plane rate quota, which the agents' own invocations share, so the sweep stays well below it.
SWEEP_STOPS_PER_SECOND = 20

# A contain of an agent that is already contained does its work again (stops sessions, schedules
# sweeps) no sooner than this after the last contain that did. Until then it is answered at once.
# Each such contain holds a slot of the containment function for up to about 20 seconds and puts up
# to three sweeps on the queue, so repeating it without a pause would take both from everyone else.
REPEAT_AFTER_SECONDS = 900
# The longest one sweep can run: one invocation of the sweeper function.
LONGEST_SWEEP_SECONDS = 900
# How long after a contain its last sweep can still be running: the last one starts after
# THIRD_SWEEP_DELAY_SECONDS and runs for at most LONGEST_SWEEP_SECONDS. A sweep that has left no
# event by then is given up: it no longer holds a repeated contain back.
SWEEPS_OVER_AFTER_SECONDS = THIRD_SWEEP_DELAY_SECONDS + LONGEST_SWEEP_SECONDS
# Once the pause is over and only a sweep that is due or running holds a repeated contain back,
# the answer says to ask again this soon: that sweep usually reports within seconds.
REPEAT_RECHECK_SECONDS = 60


def delay_words(seconds: int) -> str:
    """A delay in words: "about 90 seconds" below two minutes, "about 5 minutes" from there on."""
    if seconds < 120:
        return f"about {seconds} seconds"
    return f"about {round(seconds / 60)} minutes"
