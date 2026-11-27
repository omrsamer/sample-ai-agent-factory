# Agent Factory Portal, read-only milestone: live evidence

Recorded 2026-11-27. Region `eu-west-1` (edge stage in `us-east-1`). One
Platform account and two Workstream cell accounts of an existing reference
environment. Account ids, the external id and resource ids are kept outside
source control.

## What was deployed

| Stage | Account | How | Result |
| --- | --- | --- | --- |
| `agent-factory-portal-edge` | Platform, `us-east-1` | `cdk deploy`; then a second stack of the same stage created and deleted through a CloudFormation role holding only the rendered `portal` execution document | Complete; scoped create and delete succeeded |
| `agent-factory-portal-fleet-reader` | Cell 1 (same account as Platform) | `cdk deploy` | Complete |
| `agent-factory-portal-fleet-reader` | Cell 2 | Created through a CloudFormation role holding only the rendered `portal-cell` execution document | Complete |
| `agent-factory-portal` | Platform | Created and twice updated through a CloudFormation role holding only the rendered `portal` execution document | Complete |

Deploying through the scoped documents found and fixed four gaps before this
record was written (key custody, truncated generated names, log delivery
actions, the bootstrap version parameter).

## Checks

`tests/integration/test_agent_factory_portal.py`, 14 of 14 passed against the
deployed portal, run after the final bundles were deployed:

| Positive | Negative twin |
| --- | --- |
| A signed-in user in a persona group reads every data route (200) | No token and a forged token are refused (401) |
| The same user reads `/users/me` | A signed-in user in no persona group is refused (403) |
| `GET` on a data route succeeds | `POST`, `PUT`, `PATCH` and `DELETE` have no route |
| The portal reads all three configured cells through the fleet reader role | Another principal of the Platform account, with the correct external id, is denied `sts:AssumeRole` on that role |
| The Registry tool records are returned (`tool-echo`, `tool-ping`) | not applicable |
| A client-side route resolves to the application shell | A missing file is not served the shell |

Sign-in in these checks is real: Amazon Cognito SRP with TOTP enrolment for
users the run creates and deletes.

Browser run (headless Chromium against the deployed site): sign-in through the
Cognito hosted page with a TOTP code, then every screen. No page error, no
console error, and the only HTTP method the application issued to the API was
`GET`.

Web ACL: requests from a source outside the allow list were blocked (web ACL
log, rule `BlockSourcesOutsideAllowList`). That run also showed the block being
served as the application shell, which was fixed (a block now stays a 403);
the fix is pinned by the conformance suite. A request from outside the allow
list was not repeated after the fix.

Agent record publisher (`pipelines/publish_agent_record.py`): exercised against
a temporary Registry created for the purpose and deleted afterwards (create,
unchanged, update, submit to `PENDING_APPROVAL`, refusal to overwrite a foreign
record; no residue). The reference environment's Registries were not written
to.

## What the live data showed

Two Runtimes across the two cell accounts, both shown as "Discovered, not
registered" because the Registries hold tool records only; five Gateways; six
Guardrail profiles; fleet health "No data" for every cell because the accounts
have no CloudWatch alarms; an access graph with nodes and no edges for the same
reason as the discovered agents.

## Not covered by this evidence

- Microsoft Entra ID sign-in (synthesis and unit tests only; no tenant was used).
- Workforce SAML federation through AWS IAM Identity Center.
- A Gateway with an attached Policy Engine, alarms in a cell, and an evaluation
  gate result: none exists in the environment, so those views are covered by
  fixtures only.
- The agent record step running inside the Workload pipeline.
- Teardown of the portal stacks (they are left running for review).
