# Agent Factory Portal, inventory, containment and life after approval: live evidence

Recorded 2026-11-27 and 2026-11-28. Region `eu-west-1` (edge stage in `us-east-1`; the
CloudWatch Omni domains of this environment are in `us-west-2`). One
organization management account, one Platform account that also hosts a cell,
and one further Workstream cell account. Account ids, the external id and
resource ids are kept outside source control.

This record covers what was added after the governed-actions milestone: the
organization discovery Registry, incident containment with background sweeps,
the hand-off to Amazon CloudWatch Omni, the external inventory reader, an
agent's life after approval (periodic review, retirement, the evidence
document), and the hardening that two independent reviews led to. The
read-only and governed-actions milestones are recorded in
`agent-factory-portal-read-only-milestone.md`.

## What was deployed

| Stage or step | Account | How | Result |
| --- | --- | --- | --- |
| Trusted access for `agent-registry.amazonaws.com`, delegated administrator | Management | AWS Organizations API | Enabled; the Platform account is the delegated administrator |
| `agent-factory-portal-discovery-registry` | Platform | `cdk deploy` by an operator (creating a Registry is a protected authority) | Complete; auto-detection `ACTIVE`, scope `ORGANIZATION` |
| `agent-factory-portal-containment` | Cell 2 | Created and updated through a CloudFormation role holding only the rendered `portal-cell` execution document | Complete |
| `agent-factory-portal-fleet-reader` | Cell 1 and cell 2 | Updated (cell 2 through the scoped role) | Complete; 16 read actions, no write action |
| `agent-factory-portal-external-reader` | Cell 2 | Created through the scoped role, exercised, deleted | Complete; role and policy gone after deletion |
| `agent-factory-portal` | Platform | Updated through a CloudFormation role holding only the rendered `portal` execution document | Complete, including the sweep queue, its dead-letter queue, two alarms, the sweeper function and its event source mapping |
| `agent-factory-portal`, a second environment | Platform | Created from nothing through the same role, exercised, removed with the teardown script | Complete: created, the action and lifecycle modules passed against it (15 of 15), deleted on the first attempt, nothing left behind |

`cdk synth --strict` passes for all seven portal stages.

## Organization-wide detection

- The discovery Registry held 17 detected records about 20 minutes after it
  became active: 8 Runtimes and 9 Gateways, every Runtime and Gateway of the
  management account in the Region, with nothing deployed in that account.
- None of the Platform account's own five resources had been detected four
  hours after activation. They are in the inventory through the cell reader.
  This is why the documentation asks for the Platform account to be listed as
  a cell when it hosts Runtimes or Gateways.
- In the portal the inventory of this environment is 11 agents: 2 registered
  and detected, 9 detected only, of which 8 are in an account with no reader
  role. Each of those is listed with its account, Region and inbound
  authorizer, and every panel about it answers.

## Checks

Five live modules against the deployed portal, run after the final bundles
were deployed. Every refusal has a positive twin in the same run.

| Module | Result |
| --- | --- |
| `tests/integration/test_agent_factory_portal.py` | 14 of 14 passed |
| `tests/integration/test_agent_factory_portal_actions.py` | 6 of 6 passed |
| `tests/integration/test_agent_factory_portal_inventory.py` | 10 of 10 passed |
| `tests/integration/test_agent_factory_portal_containment.py` | 16 of 16 passed |
| `tests/integration/test_agent_factory_portal_lifecycle.py` | 9 of 9 passed |

The containment module has one more check for an account shared by several
tenants. It needs cells of three tenants in the validation Runtime's account,
so it was run in that configuration, which was then removed: passed.

### Inventory, export and Omni

| Positive | Negative twin |
| --- | --- |
| A signed-in persona reads the fleet summary, the export and the observed agents (200) | No token and a forged token are refused (401); a user in no group is refused (403) |
| The fleet summary's counts by state, risk level and flag equal the inventory | |
| Every agent is in one state; no Runtime is listed twice | |
| Every risk level equals the highest severity among its reasons | |
| An agent detected in an account with no reader role is listed and all eight panels about it answer 200 | Its containment state is `unknown` and containment is not offered |
| The registered agent whose owner group is in the roster is not flagged | The one whose owner group is not in the roster is flagged ownerless, with the reason |
| The CSV and JSON exports hold exactly the inventory; no cell starts with a formula character | An unknown format is refused (422) |
| The portal's role reads the Omni Context Graph (one IAM action, no access grant) and lists agents only | A window outside 1 to 168 hours is refused (422) |

### Containment

Run against a validation Runtime tagged for the purpose, never against a
deployed agent. The effect was measured with the cell account's own
credentials, not through the portal.

| Positive | Negative twin |
| --- | --- |
| A `security` user who holds the tenant contains the agent (200) | A `developer` and a `readonly` user are refused (403, CON-01-N); an `sre` user without the tenant is refused (403, CON-04-N); no token (401); no reason (422). After every refusal the policy is unchanged and the agent answers |
| | None of those refusals is in the Runtime's history: a caller without the role or the tenant writes nothing there |
| Invocation is refused for a new session and for the session that was running | |
| The running session is found and stopped | |
| A second contain changes nothing and does not replace the person on record | While the sweeps of the first are still to run it answers at once, stops nothing and schedules nothing |
| A different person releases the agent (200) and invocation works again | The person who contained it is refused (403, CON-03-N); a `developer` and an `sre` user are refused (403, CON-02-N). After every refusal the agent is still contained |
| A statement that was in the Runtime's resource policy before is identical during containment and after release | |
| The portal's containment function acts through the cell's role | Another principal of the Platform account cannot assume that role, with the right external id (AccessDenied) |
| | An agent whose cell did not deploy the containment stage answers 409 and is unchanged |
| The Runtime's history holds each intent and each result about it, and the refusal of the person who contained it asking to release it, with the person and the reason | A caller without the role or without the tenant is refused and leaves nothing in the history |
| The portal's own statement reads as contained | A statement planted in the cell with the portal's identifier and a condition nobody meets (the service accepted it, and invocation went on working) reads as not contained; the next contain replaces it and invocation is then refused |
| A different person releases under the Runtime's ARN | The person who contained it asks to release under three other spellings of the ARN that the service itself accepts (another partition string): refused each time (422), and still on record as the holder |
| A request through Amazon API Gateway with a real token is served | The three action functions invoked directly with claims in the event and no token, with a real token whose content was changed, with the same claims unsigned, and with a string that is no token: 401 each. Claims of a responder in the event beside a developer's real token: 403 (CON-01-N). Nothing changed. The read function invoked the same way: 401 without a token, and beside a developer's real token it answers as the developer |
| A release by a second person finds who holds the containment | The entries a release reads are the contain's intent and result and nothing after them: a contain asked for again, the sweeps and the refused release were stored beside them (read from the audit table). Three refused releases by the person who contained the agent left one entry |
| In an account shared by three tenants, a Runtime tagged for a tenant is contained by that tenant's responder | With no tag, and with a tag naming a tenant the account does not host, the same responder is refused (CON-05-N). After the tag is changed to another tenant of the account, that tenant's responder cannot release (CON-06-N). A registration naming the Runtime by someone who does not hold every tenant of the account is refused (REG-13-N) |
| A `security` user contains the Runtime through a registration's id | A registration that names the Runtime for another tenant does not change the tenant that decides (the event carries the cell's tenant) |
| A different person releases it, under the Runtime's own id | The person who contained it is refused under the Runtime's id and under the registration's id (403, CON-03-N) |
| The roles that can act read who contained the agent, why, and the history | A `developer` and a `readonly` user read that it is contained and since when, and nothing else |

Measured in the final run: the first refusal came with the first call after
the action and no call succeeded after it; after the release the first
successful call came 30 seconds later, while seven calls in ten were still
refused; 355 sessions of the last eight hours were found (all through log
stream names, none through spans), 3 were still running and were stopped, 352
had already ended. The second sweep, two minutes later, asked for 362
sessions and stopped 1. In an earlier run five sessions started after the
contain, on hosts that had not applied the deny yet, and none was running
after the second sweep.

Enforcement delay, measured separately with steady calls (one new session and
one reused session per second) on the same Runtime, twice:

| | Run 1 | Run 2 |
| --- | --- | --- |
| After the deny statement is written: last successful call | 39 seconds (4 of 552 calls succeeded) | 52 seconds (3 of 274) |
| After it, successful calls | none in the remaining 260 seconds | none in the remaining 98 seconds |
| After the statement is removed: last refused call | 263 seconds (120 of 308 calls refused) | 269 seconds (177 of 680) |
| After it, refused calls | none in the remaining 37 seconds | none in the remaining 450 seconds |

The service applies a resource policy change host by host, and closing is
faster than reopening. The portal states 90 seconds for a contain and 5
minutes for a release, and the live test asserts "closed" as 45 seconds with
no successful call.

Measured directly, with the deployed target role's policy document as a
session policy (so exactly its permissions): reading, writing, reading back
and deleting the resource policy, listing endpoints, listing session log
stream names and stopping a session all succeed; invoking the Runtime,
reading its configuration, reading a log event and starting a Logs Insights
query are refused.

Facts about the service that the design relies on, each observed:

- A Runtime resource policy statement must name exactly the Runtime's ARN as
  its resource; a list or a wildcard is rejected.
- The service accepts the six invoke actions in the deny statement.
- The denial applies to an administrator of the same account and to a session
  that is already running.
- Enforcement is eventually consistent: in one run a call on a running session
  still succeeded 10 seconds after the statement was written and was refused
  at 25 seconds.
- No API lists a Runtime's sessions. A session that writes output has a log
  stream named `runtime-logs-<session id>`; a session of an instrumented agent
  has spans carrying `session.id`. The validation Runtime is not instrumented,
  so every session in the run was found through the log streams.
- Stopping a session that has ended, and deleting a policy that does not
  exist, answer `ResourceNotFoundException`; both are treated as done.

### Background sweeps

A contain answers once the deny statement is verified and leaves the rest to
a sweeper function, fed by a queue: one sweep two minutes later, one after
fifteen, and one at once when the request left something undone.

| Positive | Negative twin |
| --- | --- |
| The second sweep of a contain runs about two minutes after it, carries the contain's request id, and the view then says since when no session is running | After the release that statement is gone from the view, and a sweep that arrives later stops nothing and records that the Runtime is no longer contained |
| A session that started after the contain, on a host that had not applied the deny yet, is no longer running after the second sweep (five such sessions in one run) | |
| The containment function's role sends a message and the sweeper's receives it | An administrator of the Platform account is refused when sending, receiving, deleting, hiding and purging a message (AccessDenied, five of five) |
| A sweep of a contain runs once | The sweeper invoked directly with an invalid message, a request id no contain has, a replay of the sweep that ran, and two records at once: nothing run, nothing added to the history. The third sweep sent before it was due: refused, nothing added |
| A sweep request written by the containment function is run | Six messages that are not sweep requests (sent before the queue was restricted): not JSON, JSON of another kind, a Runtime in an account that is no cell, an extra field naming a role to assume, a sweep number that does not exist, and a well-formed request for a Runtime that was not contained. None stopped a session, none came back, and the dead-letter queue stayed empty |

Measured: a sweep asked the service to stop each of 426 to 462 sessions of
the last eight hours in 21.5 to 23.5 seconds, which is the sweeper's own cap
of 20 per second; the service did not push back. Only a few of those sessions
were live: no API says which, so every sweep asks for all of them.

### Life after approval

| Positive | Negative twin |
| --- | --- |
| An approver confirms a periodic review with a date inside the window; the record is unchanged and the review date and reviewer are shown | A developer is refused (403); a date today, more than 366 days ahead, or malformed is refused (422); a record that is not approved is refused (409) |
| A registration that names a review date inside a year is accepted, and its approval counts as a review with that date | A registration that names a date 800 days ahead is refused (422) |
| A registration approved with no review date is due a year after its approval | |
| A record changed, submitted and approved three more times has one latest attestation, replaced each time (read from the audit table) | |
| Another approver confirms the review of a record | The person who submitted the record is refused (403, REV-05-N); a second confirmation the same day is refused (409, REV-06-N) |
| An approver retires a registration; it is DEPRECATED and a second retire changes nothing | A developer is refused (403); afterwards approve, reject, submit, review and update are refused (409). Seven refused approvals left one entry in the record's history |
| The evidence document downloaded right after the retirement says DEPRECATED and lists create, submit, approve and retire | Without a token: 401. The document holds no token and no account id outside an ARN |
| A registration in a tenant an approver does not hold stays as it was | That approver tried approve, reject, retire and review three times each: 403 every time, and nothing in the record's history |
| A retired registration with nothing deployed asks for no attention: no risk level, no flag, not under Needs attention | |

### Hardening measured on the deployed stack

- **Request budgets.** A flood of signed-in reads (900 in a few seconds, more
  than half of them throttled) used to throttle 25 of 45 contain requests sent
  at the same time; with a budget of their own, none of the contain requests
  was throttled from outside its route. 600 requests with no token at about
  100 per second were all answered 401 and none 429, so a caller without a
  token cannot use up a budget. A signed-in user with no authority can still
  call the contain route itself: at 30 refused requests per second for 20
  seconds, with the functions warm, every request of a responder was served;
  at 90 per second, 2 of a responder's 15 requests were answered 503 while
  the function scaled. The route's budget is 100 requests per second; it was
  5 for a few hours, which the second review's verification showed to be far
  too small.
- **Who a person is recorded as.** A signed-in user of the built-in user pool
  asked to change their own email, name and preferred user name: refused each
  time, and the email on record was unchanged. The same user asked to set a
  `custom:groups` attribute, from which a federated user's groups are read:
  refused.
- **The tenant tag.** With the two guard statements of the guide in a session
  policy and the session tagged with a tenant, on a live Runtime: a principal
  of another tenant could neither set the Runtime's `tenant-id` tag to its own
  tenant nor remove it; a principal of the Runtime's tenant could not give the
  Runtime to another tenant, and could set its own tenant again; another tag
  key was set and removed by both.
- **The statement's text.** The service refused a policy with a duplicate key
  in a statement and one with a leading byte-order mark, so the text the
  portal reads back cannot differ in those ways from what is enforced.
- **The Runtime's ARN.** `GetResourcePolicy` answered for the validation
  Runtime under `arn:aws-cn:`, under `arn:aws-xyz:` and with an upper-case
  Region; a different case of the Runtime id was not found. This is why the
  functions build the ARN themselves.
- **The versions list.** `ListAgentRuntimeVersions`, which the external
  inventory reader may call, returned no environment variable of a Runtime
  that has some.

### External inventory reader

Deployed with a trusted account and an external id, then removed.

| Positive | Negative twin |
| --- | --- |
| A principal of the trusted account assumes the role with the external id | Without the external id, with a wrong one, and from the cell account itself: AccessDenied |
| Lists Runtimes and Gateways, describes a Gateway, reads tags and CloudWatch metrics | Reading a Runtime's configuration (it holds the environment variables), invoking a Runtime, reading or writing a resource policy, stopping a session, tagging, listing Memory, CloudWatch Logs, Amazon S3 and IAM are refused |

### Browser

Run with a real browser against the deployed portal, signing in through the
hosted sign-in page with multi-factor authentication, as users created for
the run and removed afterwards. No page error and no failed check in any run.

| Flow | Result |
| --- | --- |
| Containment by a `security` user, with a `developer` and a `platform` user in their own sessions | 25 of 25. The confirmation names what will happen and stays disabled until a reason is entered; the developer is not offered the action and, once the agent is contained, is told so and shown nothing of who or why; the page follows the second sweep without a reload and then says since when no session is running; the same person is not offered the release; the platform user releases. The statement and the effect on invocation were read from the cell account at each step |
| Life after approval by an approver, with a developer in a second session | 19 of 19. Review and retire are offered to the approver only and stay disabled until a reason is entered; the review shows who confirmed it and leaves the record unchanged; the evidence file is saved under the server's file name and, downloaded right after the retirement, says DEPRECATED; a retired registration offers no further action; with nothing deployed its page shows no risk level and no flag, and the fleet page does not list it under Needs attention |
| Look at 1440 px and at 1024 px: fleet, agents, tool gateways, a gateway no reader read (four tabs), documentation, access graph, registrations, as a `security` and a `developer` user | 36 of 36 at each width. No horizontal overflow and no full account id in any page text; gateways that only the organization registry detected are listed as not readable, with the reason, and none of their pages claims that nothing is attached; "My tenants" keeps 2 of 11 agents for a product-team user |


## Found and fixed by deploying

1. The containment function resolved a registered agent from its Registry
   record, but its role had no Registry permission. It now holds
   `agent-registry:GetRegistryRecord` on the agent Registry and nothing else
   on a Registry.
2. Session discovery from spans finds nothing for a Runtime that is not
   instrumented, so containment would have denied new calls and stopped no
   running session. Session log stream names were added as a second source.
3. `bedrock-agentcore:ListSessions` lists the sessions of a Memory resource,
   not of a Runtime, and was removed from the target role.
4. The cell reader roles deployed before this release did not hold
   `GetResourcePolicy`, so the contained flag was unknown for every agent
   until the reader stage was redeployed in each cell. The upgrade note in
   the documentation says so.
5. The first risk rules labelled a registration with an owner group and no
   named sponsor as ownerless, and a registration waiting for an approver as
   unregistered. Reasons now name the cause they found, and a test builds the
   real-shaped records.
6. The CloudFormation resource type of the Registry takes
   `AutoDetectionEnabled` and `AutoDetectionScope`; the nested form found in
   the API is rejected.
7. The portal first said that a policy change is enforced within about 30
   seconds. Steady calls showed up to 52 seconds for a contain and four and a
   half minutes for a release. The responses, the user interface and the
   documentation now state the measured figures, and the live test no longer
   accepts three matching answers in a row as proof.
8. On a Runtime with more sessions than the limit, the result read "153 of
   200 sessions stopped" and did not say that the list had been cut. The limit
   is now 1000 per action, and a cut list makes the result partial and says
   that more sessions may be running.
9. With CORS configured on the HTTP API, API Gateway drops the CORS headers a
   function sets, so the web application could not read the file name of a
   download. The API now exposes `Content-Disposition` (checked from the
   portal's origin; another origin receives no CORS header).
10. CloudFormation tags the event source mapping it creates for the sweeper,
    and the scoped execution role was refused that call, so the first update
    rolled back. The rendered policy now allows tagging a mapping.
11. Deleting that mapping through the scoped role failed too, and only a
    create from nothing followed by a delete showed it: after the delete,
    CloudFormation reads the mapping back, and for a mapping that no longer
    exists AWS Lambda authorizes that read against every resource, so a
    permission scoped to the function or to the mapping was refused and the
    stack ended in DELETE_FAILED. The policy now allows that one read
    unscoped, and the teardown script recovers a stack left in that state.
12. A teardown that failed and was run again left the log group of a
    function the first attempt had already deleted. The script now keeps such
    functions in its plan.
13. The evidence document, downloaded right after a decision, described the
    registration as it was before the decision. It is now rebuilt from a
    fresh read when a decision is newer than the inventory.
14. A retired registration with nothing deployed kept a high risk level and
    an ownerless flag that nobody could ever clear. It is now closed.
15. The pages of a gateway that only the organization registry detected read
    "none" where they should have read "not known" (tools, policy engine,
    policies, connected agents).
16. One signed-in user flooding the read routes throttled contain requests,
    because every route shared one request budget. Contain and release now
    have their own.

## Independent reviews

Two separate reviews read the code with no access to AWS: the first after the
containment stage was built, the second after life after approval, the
background sweeps and token verification were added. What the first found,
and what was done:

| Finding | Fix | Proven by |
| --- | --- | --- |
| The history was keyed by the id the caller used, so a person could contain through a registration's id and release through the Runtime's id, where nobody was on record | The history belongs to the resolved Runtime | Unit tests; live: the release under the other id is refused |
| The tenant came from the registration, so a draft naming another tenant's Runtime brought it into reach | The tenant comes from where the Runtime runs; a registration decides only in a shared account, only when approved, and only among that account's tenants | Unit tests; live: the event carries the cell's tenant |
| An agent whose tenant cannot be determined could be acted on by any `security` user | Only the `platform` role | Unit tests |
| A contain whose read-back failed left nobody on record, so the same person could release | A contain that may have written the statement names a holder; with nobody on record, the first person to assert the containment holds it | Unit tests |
| The cell's containment role could run any Logs Insights query on the spans log group, and so read span content | The role has no query permission; spans as a source of session ids is a separate opt-in | Conformance; live: a query is refused |
| Who contained an agent, why, and every attempt were readable by every role | Returned only to the roles that can contain or release | Unit tests; live |
| Any signed-in user could add refused attempts to any agent's history | A caller without the role is refused before anything is resolved, and that refusal is logged, not stored under a caller-chosen key; the function has more reserved concurrency | Unit tests; live |
| The external inventory reader could read a Runtime's environment variables | It no longer holds `GetAgentRuntime` | Conformance; live |

The second review reported two high and four medium findings, and a third
high one was confirmed by measurement. The same reviewer then verified the
fixes on the committed code: both high findings were closed, one fix had
introduced a new medium finding, and lower ones remained. What was found in
the two passes, and what was done before this record was closed:

| Finding | Fix | Proven by |
| --- | --- | --- |
| A statement with the portal's identifier and any content made a contain report success without blocking anything | The statement is recognised by its exact content; anything else with that identifier is not a containment and is replaced by the next contain | Unit tests; live: planted statement |
| A responder or approver of one tenant could add refusals to another tenant's history without limit, and every decision read the whole history | Only a caller with the role and the tenant writes into a history; a refusal of someone with a part in it is written once; a decision reads a bounded part of the history | Unit tests; live: nothing in the history, one entry for seven refusals |
| The service accepts other spellings of a Runtime's ARN, and the history was keyed by the caller's spelling | The functions build the ARN from the cell; another spelling is refused before anything is read, in a request and in a registration | Unit tests; live: three spellings |
| Repeating a contain of a contained agent held the function's capacity and filled the sweep queue | A repeated contain answers at once while sweeps are pending; an alarm watches waiting sweeps; five sweeps run side by side | Unit tests; live |
| After days of sweeps and repeated contains a release could no longer find who held the containment | A release reads only the entries that can change the holder; everything else is written beside them | Unit tests; live: the two ranges read from the table |
| In a shared account, changing the Runtime's tenant tag handed a contained agent to another tenant | A release under a changed tenant is the `platform` role's only. Guard statements that tie the tag to the tenant of whoever sets it are documented and were measured; without them a principal of another tenant that may tag can still contain a Runtime that is not yet contained | Unit tests; live: three tenants; the guard measured |
| The rule against naming another tenant's Runtime did not apply in a shared account | There, the author must hold every tenant of the account | Unit tests; live |
| The sweeper ran with the full containment authority; any principal could remove a waiting sweep; every function used one session name in a cell; a sweeper invoked directly could use up another Runtime's sweep | The sweeper asks for a session in the cell that cannot write a policy; only the containment role handles queue messages; each role writes only its own kind of audit entry; a session name per function; one record per invocation, and only the sweeps a contain scheduled, once. A role of its own for the sweeper is left for later, because every cell would have to trust a second principal | Conformance; unit tests; live |
| The budget given to contain and release was small enough for any signed-in user to use up (introduced by the fix above it, found by the verification) | 100 requests per second; the remaining exposure is measured and stated | Live measurement |
| Approving one record again and again could push other records' review dates out of the inventory's read | One entry for a record, its latest attestation | Unit tests; live: one entry after four approvals, read from the table |
| The read function took the caller's role from the invocation event | It verifies the token itself, like the action functions | Unit tests; live: direct invocation |
| Lower findings: an unbounded review date, self-attested reviews, a registration with no review date never due, forced inventory reloads, a display label a user could change, a detection replacing a read gateway, an ambiguous failed write recorded as nothing written, signing keys kept without limit, a sentence that said a foreign statement does not deny | Each fixed | Unit tests; live for the review rules, the label and the review date |

Left open, and stated in the documentation: the permission that writes the
deny statement cannot be limited to that statement, and the sweeper runs
under the same role; a principal that may change the sweep queue itself, or
invoke the sweeper, is a protected authority of the Platform account; the API
endpoint is reachable from the internet, and one signed-in user who sends
tens of requests per second can degrade the read routes, and above about a
hundred per second the emergency routes; a tenant with many contained
Runtimes and very many sessions can delay other tenants' sweeps, which the
backlog alarm reports; in a shared account the tenant tag is an authority
that the account must guard; reads are not scoped by tenant; the two-person
rule is as strong as the identity provider's guarantee of one subject per
person; the scoped execution role can read every event source mapping of the
account and Region and tag any of them.

## What this record does not cover

- A production deployment of these stages.
- Organization-wide telemetry: the Omni read covers the portal's own account.
  In this environment the Omni domains are in another Region than the cells,
  so the one agent Omni observed is not one of the cells' agents.
- The Entra ID and SAML sign-in options with these stages, including token
  verification for Entra ID inside the action functions, which is covered by
  unit tests only.
- Two tools changing the same Runtime resource policy at the same moment. The
  service offers no conditional write; the action verifies by reading back.
- A Runtime with thousands of live sessions. The validation Runtime had a few
  hundred sessions in the eight hour window and a handful of them live; the
  sweeper's reach (about 17,000 sessions per sweep at its cap) is calculated,
  not measured.
- The path of a sweep that fails twice (the dead-letter queue and its alarm),
  the alarm on waiting sweeps, and delivery to a notification topic. They are
  asserted on the synthesized stack, not provoked live.
- The session policy on the sweeper's role assumption, the rule for a
  repeated contain after its sweeps have run, the limits on reloads of the
  inventory, the bound of 2,000 entries on what a release reads, and the
  48-hour limit on signing keys: unit tests only.
- Cost by allocation tag and findings of the account's security services:
  not built in this release.

## Residue

- Every live and browser run created its own users and registrations, named
  with a per-run marker, and removed exactly those. After the last run the
  user pool held no user of a run and the agent Registry no record of a run.
- The validation Runtime's resource policy held no statement after the last
  run, and its `tenant-id` tag had its original value. The sweep queue and
  its dead-letter queue were empty and both alarms were in the OK state.
- The second environment was created with a temporary agent Registry and
  removed with `scripts/agent_factory_portal_teardown.py` through the scoped
  role. `scripts/residue_inventory.py`, taken before the create and after the
  delete, listed no difference. This was done four times; the first two did
  not end that way, and items 11 and 12 above are what they found.
- The temporary configuration with three tenants in one account was replaced
  by the original one, and the stack was updated back.
- Left in place on purpose: the portal, edge, reader, containment and
  Registry stacks of the validation environment, the scoped execution roles
  used to deploy them, and the validation Runtime with its tag.

