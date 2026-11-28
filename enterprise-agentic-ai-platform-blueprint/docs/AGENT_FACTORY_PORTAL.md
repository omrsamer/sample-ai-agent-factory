# Agent Factory Portal

The Agent Factory Portal is the product surface of the Agent Factory: the place where the personas of the operating model (README section 1.3) see and use the platform's capabilities. It is opt-in. Nothing else in the blueprint depends on it, and a deployment without it behaves exactly as before.

The portal is read-only by default: the agent inventory, assurance and operations views, and the governance catalog. Two further opt-ins add decisions: governed registration and approval of agent records, and incident containment for the cells that grant it. Later milestones are listed under "Roadmap" and are not part of the tested envelope until they are validated live.

The portal is the system of record and decision for agents: which agents exist, who owns them, what they may reach, what was approved and by whom. Amazon CloudWatch Omni is the place for their telemetry: traces, sessions, topology, investigation and evaluations. The portal links to Omni rather than repeating it (see "Hand-off to Amazon CloudWatch Omni").

## Why it exists

The blueprint treats the Agent Factory as a product with four planes. Three of them were reachable only through code, descriptors and AWS consoles:

| Plane | Before | With the portal |
| --- | --- | --- |
| Developer experience | Templates, CLI and repository workflows | Golden-path catalog and onboarding intake (roadmap) |
| Platform control | Registry records and pipeline context | Governance catalog: agents, tools, Guardrail profiles, models |
| Workstream execution | Team-owned cells | Unchanged. The portal has no surface here. |
| Assurance and operations | CloudWatch, CodePipeline and Registry consoles per account | One inventory of every agent in the organization with its state, owner and risk level; fleet health, access graph, effective policy, release evidence, traces; incident containment |

## Operating-model rules it keeps

The portal is built to the rules the blueprint publishes, and the conformance suites (`tests/conformance/phase-27-agent-factory-portal.test.ts`, `phase-28-portal-governed-actions.test.ts` and `phase-29-portal-containment-and-inventory.test.ts`) pin each one.

| Rule | How the portal keeps it |
| --- | --- |
| Capabilities are consumed through code, descriptors and pipelines, not administrator sessions | The portal shows state and evidence. It is not an administration console. |
| Workstream mutation is pipeline only | The portal creates no resource in a Workstream account and holds no mutating permission there. |
| Central visibility must not become central write access | The API role and the cell fleet reader role hold read actions only. Synthesis fails if a non-read action is added to the reader. The one exception is incident containment, which a cell grants explicitly by deploying a role of its own (see "Incident containment"). |
| Tool Gateways use `AWS_IAM` in the default profile | The portal does not change any Gateway or Runtime authorizer. |
| Every denial has a positive twin | The role boundaries are asserted both ways in the conformance suite and exercised live before a release. |

## Architecture

```
 Management account (once per organization, optional)
   trusted access and a delegated administrator for AWS Agent Registry auto-detection

 Platform account
   agent-factory-portal-edge (us-east-1)   CloudFront-scope web ACL, logged
   agent-factory-portal-agent-registry     agent records, decided by a person      (opt-in)
   agent-factory-portal-discovery-registry organization-wide auto-detection         (opt-in)
   agent-factory-portal (platform Region)
     Amazon CloudFront + private Amazon S3     static web application, config.json
     Amazon Cognito user pool  or  Microsoft Entra ID   sign-in
     Amazon API Gateway HTTP API + JWT authorizer
     AWS Lambda (read-only API), role AgenticAI-PortalApi-<env>
        reads   AWS Agent Registry records (agents, tools, detections), Guardrail profiles,
                Workload pipeline executions (release evidence),
                the CloudWatch Omni Context Graph of its own account
        assumes AgenticAI-PortalFleetReader-<env> in each cell
     AWS Lambda (registrar), (approver)        governed registration and approval  (opt-in)
     AWS Lambda (containment), role AgenticAI-PortalContainment-<env>               (opt-in)
        assumes AgenticAI-PortalContainmentTarget-<env> in the cells that granted it
     Amazon DynamoDB                           append-only audit trail

 Workstream cell account (one per cell)
   agent-factory-portal-fleet-reader
     role AgenticAI-PortalFleetReader-<env>, read-only:
        AgentCore Runtime, Gateway, targets, Policy Engine and policies, resource policy
        CloudWatch alarms and metrics
        Logs Insights over the spans log group
     trusts only AgenticAI-PortalApi-<env> of the Platform account, with an external id
   agent-factory-portal-containment                                                 (opt-in)
     role AgenticAI-PortalContainmentTarget-<env>: Runtime resource policy, session stop
     trusts only AgenticAI-PortalContainment-<env> of the Platform account, with an external id
   agent-factory-portal-external-reader                                             (opt-in)
     role AgenticAI-ExternalInventoryReader-<env>: read-only inventory for an external tool
```

The web application loads `config.json` at start, so one build serves every environment. The read API has `GET` routes only. Each opt-in adds its own function, its own role and its own routes, so that a decision can never be taken with the read role.

## Personas and roles

Sign-in groups map to portal roles. The role decides what a person may see and, with the opt-ins, which decisions they may take.

| Portal role | Persona | Amazon Cognito group |
| --- | --- | --- |
| `platform` | Platform engineering | `platform-engineering` |
| `security` | Security and risk | `security-and-risk` |
| `sre` | Platform SRE | `platform-sre` |
| `finops` | FinOps | `finops` |
| `approver` | Human approvers | `human-approvers` |
| `developer` | Product and domain teams | `product-teams` |
| `readonly` | Read-only access | `portal-readonly` |

A signed-in user who belongs to no mapped group is refused.

With governed actions on, roles also carry authorities, and tenants come from `agenticai/portalGroupTenantMap`:

| Portal role | Registrar (create, change, submit, delete) | Approver (approve, reject, retire, attest a review) | Tenants |
| --- | --- | --- | --- |
| `platform` | yes | yes | every tenant |
| `developer` | yes | no | tenants of the user's groups |
| `approver`, `security` | no | yes | tenants of the user's groups |
| `sre` | no | no | tenants of the user's groups, used for containment only |
| `finops`, `readonly` | no | no | none |

With containment enabled for a cell:

| Portal role | Contain | Release | Condition |
| --- | --- | --- | --- |
| `security`, `platform` | yes | yes | Holds the agent's tenant (`platform` holds every tenant). The person who contained an agent cannot release it, whatever their role. |
| `sre` | yes | no | Holds the agent's tenant |
| others | no | no | |

The tenant that decides is the tenant of the place the Runtime runs in (the cells configured for its account and Region), not the tenant a registration claims. Who contained an agent, why, and the history of attempts are shown to these three roles only; every other role sees whether an agent is contained and since when.

## Sign-in options

**Amazon Cognito (default).** The stack creates a user pool with no self sign-up, required TOTP MFA and the authorization code flow with PKCE. For workforce sign-in, create a SAML application for the portal in AWS IAM Identity Center and pass its metadata URL as `agenticai/portalSamlMetadataUrl`; users then sign in through Identity Center and the user pool holds no passwords. Send the user's group names in a SAML attribute (default name `groups`) and map those names to portal roles with `agenticai/portalGroupRoleMap`.

**Microsoft Entra ID.** Set `agenticai/portalIdentityProvider=entra` and supply `agenticai/portalEntra` (`tenantId`, `spaClientId`, `apiAudience`, `apiScope`) plus `agenticai/portalGroupRoleMap`, which maps Entra app roles or group object ids to portal roles. No user pool is created; the API validates tokens against the tenant issuer.

## Deploy

Build the two application bundles first (see `apps/agent-factory-portal/README.md`):

```bash
(cd apps/agent-factory-portal/api && ./build.sh)
(cd apps/agent-factory-portal/web && npm ci && npm run build)
```

1. Edge web ACL, in us-east-1, Platform account:

   ```bash
   npx cdk deploy --context stage=agent-factory-portal-edge \
     --context agenticai/portalEnvironment=nonprod \
     --context agenticai/portalAccountId=<PLATFORM_ACCOUNT> \
     --context agenticai/portalAllowedCidrs=<CIDR>[,<CIDR>]
   ```

   The portal is a workforce application, so the stage requires an allow list. Pass `agenticai/portalExposure=public` only when it must be reachable from any address.

2. Fleet reader role, once per Workstream cell account, with that account's credentials:

   ```bash
   npx cdk deploy --context stage=agent-factory-portal-fleet-reader \
     --context agenticai/portalEnvironment=nonprod \
     --context agenticai/portalCellAccountId=<CELL_ACCOUNT> \
     --context agenticai/portalAccountId=<PLATFORM_ACCOUNT> \
     --context agenticai/portalExternalId=<EXTERNAL_ID>
   ```

   When the Platform account also hosts Runtimes or Gateways, deploy the reader there too and list the account as a cell.

3. Portal, Platform account and Region:

   ```bash
   npx cdk deploy --context stage=agent-factory-portal \
     --context agenticai/portalEnvironment=nonprod \
     --context agenticai/portalAccountId=<PLATFORM_ACCOUNT> \
     --context agenticai/portalWebAclArn=<PortalWebAclArn output of step 1> \
     --context 'agenticai/portalCells=[{"tenantId":"<TENANT>","agentId":"<AGENT>","accountId":"<CELL_ACCOUNT>","region":"<REGION>","externalId":"<EXTERNAL_ID>","pipelineName":"<WORKLOAD_PIPELINE>"}]'
   ```

Keep real account ids, the external id and the cell list outside source control, as with the rest of the `agenticai/*` context.

### Governed registration and approval (opt-in)

Registration and approval record decisions about agents. They deploy nothing: deployment still happens only through the Workload pipeline of the owning cell.

Agent records live in their own Registry. The Platform Registry approves automatically, because the Platform pipeline is the authority for tool records; an agent record is decided by a person, so its Registry has no auto-approval rule and a submitted record waits in `PENDING_APPROVAL`. Creating a Registry is a protected authority, so operators deploy it in its own stage and the portal stack only receives its id and ARN (the same custody rule as the Omni hub keys):

```bash
# Operators, once per environment:
npx cdk deploy --context stage=agent-factory-portal-agent-registry \
  --context agenticai/portalEnvironment=nonprod \
  --context agenticai/portalAccountId=<PLATFORM_ACCOUNT>

# Then the portal stage with:
  --context agenticai/portalGovernedActions=true \
  --context agenticai/portalAgentRegistryId=<PortalAgentRegistryId> \
  --context agenticai/portalAgentRegistryArn=<PortalAgentRegistryArn> \
  --context 'agenticai/portalGroupTenantMap={"product-teams":["<TENANT>"],"human-approvers":["<TENANT>"]}'
```

The Workload pipeline publishes each deployed agent's record to the same Registry with `pipelines/publish_agent_record.py` (the Registry id is under `/agenticai/registry/agents/v1/<env>/id`); a record published that way has no portal submitter, so any approver may decide it.

What the opt-in adds, and what it never does:

| Added | Guarantee |
| --- | --- |
| Registrar function, role `AgenticAI-RegistryRegistrar-<env>` | Creates, changes, submits and deletes agent records in the agent Registry. Cannot decide an approval and cannot touch the Platform Registry. |
| Approver function, role `AgenticAI-RegistryApprover-<env>` | Approves or rejects a submitted record, confirms a periodic review and retires a registration. Cannot create or change one. The person who submitted a record cannot decide it, whatever their role. |
| Audit trail (DynamoDB, point-in-time recovery) | Every decision about a record, allowed or refused, with who and why. The functions can append; none can change or delete an entry. A caller who lacks the authority, or does not hold the record's tenant, is refused and leaves nothing in a history: that refusal is in the function's log with its request id. So nobody writes into the history of a record they have no part in, and each function's role can write only its own kind of entry. Every rule identifies a person by the subject id of their token; the label recorded beside it (a verified or directory-set email or user name) is for reading. |
| Rules of the registration core | An approved record cannot have its runtime, gateway, tool subscriptions, risk class or data classification changed; that needs a new registration. Any other change returns the record to draft for a new review. A registration cannot name a Runtime, Gateway or policy engine that runs in a cell of another tenant; where several tenants share an account and Region, only someone who holds all of them can register or approve a resource there, because an ARN does not say whose it is. A review date is at most 366 days ahead. |
| Token verification | The registrar, approver and containment functions verify the caller's token themselves (signature, issuer, audience, expiry), so an event handed to a function directly carries no weight. |

Where SCP-11 is attached, add the approver role to the protected authority manifest (purpose: registry), or its status decisions are denied by the organization.

### Organization-wide inventory (opt-in)

By default the inventory holds what is registered and what the cell readers see. AWS Agent Registry auto-detection adds every AgentCore Runtime and Gateway of the organization's accounts, with nothing to deploy in those accounts. That is how an agent that nobody registered, in an account the platform does not manage, becomes visible.

1. Management account, once per organization. These are AWS Organizations operations that only the management account can perform:

   ```bash
   aws organizations enable-aws-service-access --service-principal agent-registry.amazonaws.com
   aws iam create-service-linked-role --aws-service-name agent-registry.amazonaws.com
   aws organizations register-delegated-administrator \
     --account-id <PLATFORM_ACCOUNT> --service-principal agent-registry.amazonaws.com
   ```

2. Platform account (the delegated administrator), once per Region:

   ```bash
   npx cdk deploy --context stage=agent-factory-portal-discovery-registry \
     --context agenticai/portalAccountId=<PLATFORM_ACCOUNT>
   ```

3. The portal stage with `agenticai/portalDiscoveryRegistryId` and `agenticai/portalDiscoveryRegistryArn` (outputs of step 2).

What to expect, from the service documentation and from the live run recorded in `docs/evidence/`:

- An organization can have one organization-scoped Registry per Region, and it detects in its own Region only. Deploy the stage in each Region the organization runs agents in.
- The first discovery of existing resources can take up to 20 minutes. After that the Registry follows creations, changes and deletions.
- Detected records are drafts named `aws-autodetected-<account>-<region>-<resource>`. The portal reads them and never edits, submits or approves them: the decision about an agent is its registration in the agent Registry.
- In the live run every Runtime and Gateway of the organization's management account was detected, and none of the Registry's own account. List the Platform account as a cell (step 2 of "Deploy") when it hosts Runtimes or Gateways; the cell reader covers it.
- Removing it needs three steps in order, because detected records cannot be deleted while detection is on: turn auto-detection off on the Registry, delete its records, then delete the stack.

### Incident containment (opt-in, per cell)

Containment is the one write the portal can perform in a Workstream account. A cell grants it by deploying a role of its own; a cell that does not deploy it cannot be contained from the portal.

```bash
# Cell account, with that account's credentials:
npx cdk deploy --context stage=agent-factory-portal-containment \
  --context agenticai/portalEnvironment=nonprod \
  --context agenticai/portalCellAccountId=<CELL_ACCOUNT> \
  --context agenticai/portalAccountId=<PLATFORM_ACCOUNT> \
  --context agenticai/portalExternalId=<EXTERNAL_ID>

# Then the portal stage, with "containment": true on that cell in agenticai/portalCells
# (governed actions must be on: containment uses the same audit trail).
```

Running sessions are found through the names of the Runtime's session log streams. A cell whose agents are instrumented but write no output can add its spans as a second source: deploy the containment stage with `--context agenticai/portalContainmentSpans=true` and set `"containmentSpans": true` on the cell. That grants the cell's containment role a Logs Insights query on the spans log group, and a role that can run a query there can read span content (prompts, tool output), so it is off by default.

See "Incident containment" below for what it does and what it cannot do.

#### Accounts shared by several tenants

The reference model is one cell per account, and there the account itself says whose a Runtime is. When cells of several tenants are configured for one account and Region, the portal cannot tell from an ARN whose a Runtime is, so:

- For containment, the Runtime's own `tenant-id` tag decides, and only when it names one of the tenants configured there. A Runtime with no such tag, or with a tag the portal's role in the cell cannot read, can be contained and released by the `platform` role only.
- A registration that names a Runtime, Gateway or policy engine in that account can be created and approved only by someone who holds every tenant configured there.

That makes the tag an authority. Whoever can change it decides which tenant's responders may act, so in a shared account reserve the tag key for the cell's pipeline. Attach this statement as a service control policy, or put it in the permissions boundary of every other role of the account:

```json
{
  "Sid": "OnlyThePipelineSetsTheTenantOfARuntime",
  "Effect": "Deny",
  "Action": ["bedrock-agentcore:TagResource", "bedrock-agentcore:UntagResource"],
  "Resource": "arn:aws:bedrock-agentcore:*:*:runtime/*",
  "Condition": {
    "ForAnyValue:StringEquals": { "aws:TagKeys": ["tenant-id"] },
    "ArnNotLike": { "aws:PrincipalArn": "arn:aws:iam::*:role/<DEPLOYMENT_ROLE_OF_THE_CELL_PIPELINE>" }
  }
}
```

Checked on a live Runtime with the deny in a session policy: setting the key, removing it, and setting it together with another key are refused; other tag keys are not affected. The portal adds its own guard on top: if the tenant that decides is not the one an agent was contained under, only the `platform` role can release it.

### Hand-off to Amazon CloudWatch Omni (optional)

Add `"omniDomainUrl": "https://<domain id>.cloudwatch-omni.global.app.aws"` and `"omniRegion": "<REGION>"` to a cell in `agenticai/portalCells`, and `"accountAlias": "<name>"` to show a name instead of an account id. The domain URL is the `domainEndpointUrl` of the account's Omni domain (`aws cloudwatchomni get-domain`).

### External inventory reader (optional)

For a governance tool outside AWS that needs to read the agent inventory of an account, deploy a role it can assume instead of creating an access key:

```bash
npx cdk deploy --context stage=agent-factory-portal-external-reader \
  --context agenticai/portalEnvironment=nonprod \
  --context agenticai/portalCellAccountId=<ACCOUNT_TO_READ> \
  --context agenticai/externalReaderTrustedAccountId=<TOOL_ACCOUNT> \
  --context agenticai/externalReaderExternalId=<EXTERNAL_ID> \
  [--context agenticai/externalReaderTrustedPrincipalArn=<ROLE_ARN_IN_TOOL_ACCOUNT>] \
  [--context agenticai/externalReaderSourceCidrs=<CIDR>[,<CIDR>]]
```

The role `AgenticAI-ExternalInventoryReader-<env>` can list Runtimes with their versions and endpoints, list and describe Gateways, read tags and read CloudWatch metrics. It cannot read a Runtime's own configuration (which holds its environment variables), invoke an agent, read a policy, a log or any data, or change anything.

### Upgrading

A portal release can add a read to a cell's roles. Redeploy the `agent-factory-portal-fleet-reader` stage in every cell account when you upgrade the portal stage, and the `agent-factory-portal-containment` stage in every cell that deployed it. Until a cell's reader is current, what the new read feeds is shown as unknown for that cell (for example the contained flag), never as a wrong value; until its containment role can read a Runtime's tags, a Runtime in an account shared by several tenants can be contained by the `platform` role only.

The portal's functions assume a cell's roles under the session names `portal-reader`, `portal-containment` and `portal-sweeper`. A cell that restricts the session name in a role's trust policy must allow them.

### Context reference

| Key | Stage | Meaning |
| --- | --- | --- |
| `agenticai/portalEnvironment` | all | `nonprod` or `prod`; selects the Registry the portal reads |
| `agenticai/portalAccountId` | all | Platform account that hosts the portal |
| `agenticai/portalAllowedCidrs`, `agenticai/portalAllowedIpv6Cidrs` | edge | Sources allowed through the web ACL |
| `agenticai/portalExposure` | edge | `allow-list` (default) or `public` |
| `agenticai/portalWebAclArn` | portal | Output of the edge stage |
| `agenticai/portalIdentityProvider` | portal | `cognito` (default) or `entra` |
| `agenticai/portalSamlMetadataUrl`, `agenticai/portalSamlGroupsAttribute` | portal | Workforce federation for the Cognito option |
| `agenticai/portalEntra` | portal | Entra settings (JSON) |
| `agenticai/portalGroupRoleMap` | portal | Group or app-role name to portal role (JSON) |
| `agenticai/portalCells` | portal | Cells the portal reads (JSON array). Per cell: `tenantId`, `agentId`, `accountId`, `region`, `externalId`; optional `applicationId`, `environment`, `pipelineName`, `alarmNamePrefix`, `accountAlias`, `containment`, `containmentSpans`, `omniDomainUrl`, `omniRegion` |
| `agenticai/portalModelAllowlist`, `agenticai/portalGuardrailTag` | portal | Catalog inputs |
| `agenticai/portalApiCodePath`, `agenticai/portalWebDistPath` | portal | Override the bundle locations |
| `agenticai/portalLogsKeyArn`, `agenticai/portalEdgeLogsKeyArn` | portal, edge | Operator-provisioned customer managed key for the log groups (optional). The stacks never create or tag a key. |
| `agenticai/portalAlarmTopicArn` | portal | Operator-provisioned Amazon SNS topic that is told when a background containment sweep could not be processed (optional). The stack creates no topic. |
| `agenticai/portalGovernedActions` | portal | `true` adds registration and approval (default: off, read-only) |
| `agenticai/portalAgentRegistryId`, `agenticai/portalAgentRegistryArn` | portal | The agent Registry (outputs of the agent-registry stage); required with governed actions |
| `agenticai/portalGroupTenantMap` | portal | Group or app-role name to the tenant ids its members may act for (JSON) |
| `agenticai/portalRegistryId`, `agenticai/portalRegistryArn` | portal | Use a given Platform Registry instead of the environment's default |
| `agenticai/portalRetainData` | portal | Retain the user pool and buckets on deletion (default: prod only) |
| `agenticai/portalDiscoveryRegistryId`, `agenticai/portalDiscoveryRegistryArn` | portal | The organization discovery Registry (outputs of the discovery-registry stage); adds organization-wide detection to the inventory |
| `agenticai/portalOwnerGroups` | portal | The owner groups that exist (comma-separated). A registration whose owner group is not in the list is flagged. Without it, only a missing owner group is flagged |
| `agenticai/portalInactiveDays` | portal | Days without an invocation before an agent is flagged inactive (default 30) |
| `agenticai/portalCellAccountId`, `agenticai/portalExternalId`, `agenticai/portalSpansLogGroupNames` | fleet reader, containment | Cell account, shared external id, span log groups |
| `agenticai/portalContainmentSpans` | containment | `true` also grants the containment role a query on the spans log group, as a second source of session ids (default: off) |
| `agenticai/externalReaderTrustedAccountId`, `agenticai/externalReaderExternalId`, `agenticai/externalReaderTrustedPrincipalArn`, `agenticai/externalReaderSourceCidrs` | external reader | Who may assume the external inventory reader role, and from where |

## What the portal reads

| View | Source |
| --- | --- |
| Agents | Registry records with schema `agenticai.agent-governance/1.0`, merged with the AgentCore Runtimes the cell readers see and, when configured, the Runtimes the organization discovery Registry detected. A Runtime seen by several sources is one agent. See "Inventory and risk level". |
| Tool gateways | AgentCore Gateways of each cell, their targets, and the Registry tool records (`agenticai.tool-governance/1.0`) |
| Effective policy | The Gateway's AgentCore Policy Engine: Cedar text as deployed, and the mode (`OFF`, `LOG_ONLY`, `ENFORCE`) |
| Access graph | Owner group to agent, agent to Tool Gateway, with whether a policy engine is attached |
| Release evidence | Executions of the cell's Workload pipeline, including the evaluation gate result |
| Traces and metrics | CloudWatch Logs Insights over the cell's spans log group and CloudWatch metrics for the Runtime |
| Fleet health | CloudWatch alarms per cell: critical, needs attention, healthy, or no data |
| Guardrail profiles, models | Amazon Bedrock Guardrails in the Platform account and the configured model allow-list |
| Containment state | The Runtime's resource policy, read through the cell reader, and the audit trail |
| Agents observed in telemetry | The Amazon CloudWatch Omni Context Graph of the portal's own account, agents only |

## Inventory and risk level

Every agent is in exactly one inventory state:

| State | Meaning |
| --- | --- |
| Registered and detected | A registration exists and its Runtime is seen by a cell reader or by organization detection |
| Registered only | A registration exists and no source sees a Runtime for it |
| Detected only | A Runtime exists and nobody registered it |

Agents that CloudWatch Omni observes in telemetry and that are in none of these states are listed separately as observed only (see "Hand-off to Amazon CloudWatch Omni").

An agent detected in an account with no cell reader is listed with its account, Region and inbound authorizer. Its health, traces, policy and containment state are shown as not readable, not as empty.

Each agent carries five flags, each true, false or unknown: unmanaged (no approved registration), ownerless (no owner group, or an owner group that is not in `agenticai/portalOwnerGroups`), review overdue, inactive, contained. The fleet page counts them, including for how many agents a flag is unknown.

The risk level (low, medium, high, critical) is not a score. A fixed table of rules each looks at one fact; a rule that applies contributes one reason with a fixed severity; the level is the highest severity among the reasons; a fact that is not known triggers nothing. Every agent's page lists its reasons, so the level can always be explained. The table is in `apps/agent-factory-portal/api/README.md` ("Flags and risk") and the function is `portal_api/risk.py`.

The inventory can be downloaded as CSV or JSON (`GET /api/v1/agents/export`), one row per agent with its state, flags, risk level and reasons.

## Life after approval

An approval is not the end of an agent's governance. Three things follow it, all in the portal, none of which changes a cell.

- **Periodic review.** A registration carries a review date. A person with the approver authority for the agent's tenant confirms a review and sets the next date (at most 366 days ahead). The person who submitted the registration cannot confirm its review, and a registration's review can be confirmed once a day. The confirmation is recorded in the audit trail and never touches the record, because a change to a record returns it to draft. An approval of a registration that names a review date counts as a review. An agent whose date has passed is flagged, and the flag raises its risk level.
- **Retirement.** The same authority retires a registration with a reason. It is permanent: the record can no longer be approved, changed or submitted, and bringing the agent back needs a new registration. Retiring deploys and removes nothing. While the agent's Runtime is still detected, the agent is listed as retired and still deployed, at a high risk level, until its pipeline removes it. That is the follow-up the portal keeps visible.
- **Evidence.** Every agent has one evidence document to download: what it is and where it runs, its registration as stored with its hash, every decision about it with who and why, its reviews, its containment history, its risk level with the reasons, the policy mode and policy hashes of its Tool Gateways, and its latest release. It holds no environment value, no secret and no full account id outside an ARN, and it says what it could not read. A document requested right after a decision is built from a fresh read of the inventory, so its sections do not contradict its own list of decisions. The incident record of a containment is included only for the roles that may read it.

## Incident containment

Containing an agent denies every invocation of its Runtime and stops its running sessions. Releasing it lifts the denial. It is the portal's answer to "contain the principal" in README section 9.3, and the one place where the portal writes into a Workstream account.

What it does, in the agent's cell, with the role that cell deployed:

1. Adds one statement to the Runtime's resource policy that denies the invoke actions to every principal. Every other statement is kept exactly as it was. The statement is read back before the action is reported as done.
2. Finds the Runtime's sessions and stops them. No API lists a Runtime's sessions, so their ids come from the names of the log streams the service creates per session (any agent that writes output). No log event is read and no query is run. A cell can opt in to its spans as a second source.

Release removes exactly that statement and nothing else. Nothing is deleted from the agent, its configuration or its data, and nothing is redeployed: the Workload pipeline remains the only way to change a cell.

The rules:

- Contain needs the `security`, `platform` or `sre` role; release needs `security` or `platform`. The caller must hold the agent's tenant.
- The tenant is decided by where the Runtime runs, never by what a registration says. One tenant in the Runtime's account and Region: that tenant. An account shared by several: the tenant in the Runtime's `tenant-id` tag, when it is one of them. Otherwise only the `platform` role may act. If the tenant that decides is no longer the one the agent was contained under, only the `platform` role may release it. See "Accounts shared by several tenants" under Deploy.
- The person who contained an agent cannot release it. A second person must. No role bypasses this, and it holds whichever id or spelling of the Runtime's ARN a request uses: the portal builds the ARN itself, and the history belongs to that Runtime.
- A reason is required. Every action and every failure about a Runtime is in its history with who and why, and so is a refusal of someone who holds its tenant, such as the person who contained it asking to release it. A caller without the role or without the tenant is refused and leaves nothing in the history; that refusal is in the function's log with its request id. People of one tenant cannot write into another tenant's history.
- Both actions are safe to repeat. Containing a contained agent changes nothing and does not change who is on record as having contained it. While its background sweeps are still to run, a repeated contain answers at once; after that it stops any session that is still running and schedules the sweeps again.
- The portal recognises its statement by its content, not by its name. A statement that carries the portal's identifier but does not deny invocation to every principal is reported as not contained, and the next contain replaces it.

What to know before relying on it:

- **Enforcement is not instant, and the two directions differ.** The service applies a resource policy change host by host. Measured on a live Runtime under steady calls: after a contain the first refusal came within seconds and an occasional invocation still succeeded for up to 52 seconds, none after that; after a release most calls were still refused in the first minute and some were still refused four minutes later. The portal therefore says "within about 90 seconds" for a contain and "about 5 minutes" for a release. Slow to reopen and fast to close is the safe direction, but plan a release with that delay in mind.
- **Sessions are stopped in two stages.** The action itself stops up to 1000 sessions, most recent first, within the request's time budget, and says so when a limit cut the work. Containment then finishes in the background: a sweep right away when the first one was cut short, a second two minutes later, which catches a session that started on a host that had not yet applied the deny, and a third after fifteen minutes. Each sweep is one entry in the agent's history with what it found and stopped, and the containment view says since when no session has been found running. Two alarms watch the sweeps: one when a sweep could not be processed twice and was set aside, one when sweeps have been waiting for more than an hour (`agenticai/portalAlarmTopicArn` names the topic to notify). Only the containment role can send, receive, delete or purge a message of the sweep queue, whatever another principal's own permissions are. The sweeper still treats every message as untrusted: it takes no role, account or Region from a message, it reads the Runtime's policy first, and its session in the cell can read a policy and stop a session but cannot write or delete a policy. So the most a message can cause is one more sweep of an agent the portal is containing at that moment. Every sweep asks the service to stop each session of the last eight hours, ended or not, because no API says which are live; on the validation Runtime that was about 430 calls in 22 seconds. A Runtime that writes no output has no session the portal can find; invocation is still denied, including on a session that is still running, but work already in progress inside such a session is not interrupted.
- **The policy change is not atomic.** The service offers no conditional write for a resource policy. If another tool rewrites the same policy at the same moment, the read-back fails and the action reports that it could not be verified. A write that fails in a way that may still have been applied is recorded as unknown, so that the person who asked is on record and cannot release it alone.
- **A decision reads a bounded part of the history.** A release reads back from the newest entry to the contain it is about, at most 2,000 entries, and is refused if it does not find it; an approval reads back to the latest submit in the same way. Only people with authority over the agent can add entries, a repeated contain adds one per person in fifteen minutes, and the sweeps of one contain add at most three, so the bound is reached only by sustained misuse from inside the agent's own tenant. The remedy is then in the cell: remove the portal's statement from the Runtime's resource policy there.
- **It covers the Runtime.** An agent's Gateway, Memory and identities are not touched. Revoking a tool grant or a credential is a pipeline change.
- **The permission boundary.** The role shared by the containment function and the sweeper can assume the role of the cells that granted it, read one record of the agent Registry, write and read containment histories in the audit trail (no other kind of entry), use the sweep queue and write its own two log groups; nothing else. The cell's role can read, put and delete a Runtime's resource policy, stop a session, list endpoints and session log stream names, and read a Runtime's tags. It cannot invoke, update or delete a Runtime, read its configuration, read a log event or run a query (`tests/conformance/phase-29-portal-containment-and-inventory.test.ts`). Contain and release have a request budget of their own, so traffic on the portal's other routes cannot throttle them.
- **What that boundary does not close.** IAM cannot restrict the content of a resource policy, so the permission that writes the deny statement could write any statement: whoever controls the containment function controls the invocation policy of every Runtime in the cells that opted in. Treat the portal's functions, their code and their roles as protected authorities of the Platform account, and alarm in each cell on a `PutResourcePolicy` by the containment role whose statement is not the portal's, and on any by its `portal-sweeper` session (each function uses its own role session name in a cell's CloudTrail: `portal-reader`, `portal-containment`, `portal-sweeper`). A principal of the Platform account that may invoke Lambda functions can start the sweeper directly; it treats that event as it treats a queue message. A principal of a cell account that may write a Runtime's resource policy can remove the portal's statement; the portal then reports the agent as not contained. The two-person rule counts token subjects, so it is as strong as the identity provider's guarantee of one subject per person.
- **The API endpoint.** The read API, which changes nothing, trusts the claims Amazon API Gateway passes after it has verified the token; the functions that decide verify the token themselves. The API endpoint is reachable from the internet and is protected by those checks and by request budgets, not by the web distribution's allow list. Measured: requests the authorizer refuses do not use up a budget (600 unauthenticated requests at about 100 per second were all answered 401), while one signed-in user can use up the budget the read routes share and make reads fail for everyone for as long as they keep it up; the access log names the subject.

## Hand-off to Amazon CloudWatch Omni

The portal does not repeat what Omni does. Where a cell names its Omni domain, the agent, fleet and health pages link to it in a new tab; Omni cannot be embedded in another page.

The portal also asks the Omni Context Graph which agents it observes in telemetry in the portal's own account, and compares them with the inventory. An agent that emits telemetry but is neither registered nor detected is listed as observed only.

- The read needs one IAM action on the portal's role, `cloudwatch:GetContextGraph`, pinned to the Omni Region. No Omni access grant is involved.
- An Omni space can be read only from its own account, so cells in other accounts are linked to but not read. Reading an organization's hub needs a reader role in the hub account (roadmap).
- An Omni domain sees the Region it lives in. When that differs from the cells' Region, the agents it observes there are not the cells' agents.
- What counts as observed in a time window is decided by Omni. The portal shows what the Context Graph returns for the window chosen.

## Removal

Release every contained agent first: deleting the portal does not lift a containment, and after the containment role is gone only the cell account itself can remove the statement (Sid `AgenticAIPortalContainment`) from a Runtime's resource policy.

Delete the stacks in reverse order: portal, then in each cell the containment, external reader and fleet reader stacks, then edge. The two Registries hold the system of record and are removed last and deliberately, if at all: the agent Registry when its records are no longer needed, and the discovery Registry after turning auto-detection off and deleting its records (see "Organization-wide inventory"). The teardown script refuses both by name. Use `scripts/agent_factory_portal_teardown.py` for the portal stack: its access-log bucket keeps receiving log deliveries for a while after the stack has emptied it, so a plain stack delete can fail on that bucket, and the log groups of the stack's provider functions are not stack resources. The script captures what the stack owns before deleting, retries after emptying exactly those buckets, and removes exactly those log groups. It also finishes a stack left in DELETE_FAILED by an event source mapping that is in fact gone, which an execution role rendered before this release can cause.

```bash
python3 scripts/agent_factory_portal_teardown.py --stack-name AgenticAI-AgentFactoryPortal-<env> \
  --expected-account <PLATFORM_ACCOUNT> --region <REGION>            # prints the plan
python3 scripts/agent_factory_portal_teardown.py ... --execute        # after reviewing it
```

`scripts/residue_inventory.py --global` lists what remains, including the distribution, the web ACL and its IP sets.

Changing the allow list updates the web ACL in place. The edge stack and the portal stack must not be replaced in one step: a web ACL cannot be deleted while a distribution uses it.

## Support envelope

The portal follows the blueprint's rule: the support claim stops at the tested boundary. The validated Region and identity options are recorded in README section 15 once the live evidence for a release exists; a different Region or identity source is a new validation target.

## Roadmap

| Milestone | Adds |
| --- | --- |
| Policy and access | Tool-level effective access per agent, policy change proposals as pull requests, a check before promoting a policy engine from logging to enforcing, release approval with the evidence beside it, tool subscription requests |
| Lifecycle | Owner reassignment as a governed action; reminders before a review date |
| Hardening | A record in the cell of every change the portal made there; reads scoped to the tenants a product team holds |
| Security posture | Findings of the account's threat detection and posture services as inputs to the risk level |
| FinOps and product metrics | Cost by allocation tag, budgets, tag coverage, and the platform product metrics of README section 7 |
| Developer experience | Golden-path catalog with versions and support windows, onboarding intake that produces the descriptor and pull request, "my agents" with pipeline status |
| Organization telemetry | A reader role in the Omni hub account, so the observed-only check covers the whole organization |
| Representative fleet and delegated access | A fleet of representative cells for canarying platform changes, and an optional implementation profile for per-user tool authorization |

## Provenance

The web application is derived from the Agentic Governance Platform (Apache-2.0) and is maintained independently here. See `apps/agent-factory-portal/NOTICE` and `apps/agent-factory-portal/THIRD_PARTY.md`.
