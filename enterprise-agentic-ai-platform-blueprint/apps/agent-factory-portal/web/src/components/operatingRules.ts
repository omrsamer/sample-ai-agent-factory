// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

/** The operating rules the portal follows, as the Documentation page states them. */

const READ_ONLY_RULE =
  'Central visibility does not grant central write access. This portal never changes an agent, a tool gateway, a policy or a cell.';

// With governed actions on, containment is the one thing the portal does in a cell, and only
// where the cell allows it. Saying "never changes an agent" there would not be true.
const GOVERNED_RULE =
  'Central visibility does not grant central write access. This portal never deploys, edits or deletes an agent, a tool gateway, a policy or a cell. The one governed exception is containment: where a cell has given the portal that authority, an authorised person can deny invocation of an agent and stop its sessions. It deletes nothing and a different person can release it.';

/** The third rule says what the portal can do in a cell, which depends on the feature. */
export function operatingRules(governedActions: boolean): string[] {
  return [
    'Teams consume platform capabilities through code, descriptors and pipelines, not through administrator sessions.',
    'A Workstream cell is changed only by its own pipeline.',
    governedActions ? GOVERNED_RULE : READ_ONLY_RULE,
    'The default tool gateway authorises the calling workload with AWS IAM. There are no per-end-user grants in the default profile.',
  ];
}
