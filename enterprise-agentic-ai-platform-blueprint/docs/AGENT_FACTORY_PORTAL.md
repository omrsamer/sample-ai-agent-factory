| Platform control, further governed actions | Tool subscription requests, release approval with evidence beside it, policy change proposals as pull requests, on-demand replay of a positive call and its adversarial twin in nonproduction, incident containment through the cell's kill switch |
# Agent Factory Portal

The Agent Factory Portal is the product surface of the Agent Factory: the place where the personas of the operating model (README section 1.3) see and use the platform's capabilities. It is opt-in. Nothing else in the blueprint depends on it, and a deployment without it behaves exactly as before.

The portal is read-only by default: assurance and operations views plus the governance catalog. Governed registration and approval of agent records is a second opt-in on top of it. Later milestones are listed under "Roadmap" and are not part of the tested envelope until they are validated live.

## Why it exists

The blueprint treats the Agent Factory as a product with four planes. Three of them were reachable only through code, descriptors and AWS consoles:

| Plane | Before | With the portal |
| --- | --- | --- |
| Developer experience | Templates, CLI and repository workflows | Golden-path catalog and onboarding intake (roadmap) |
| Platform control | Registry records and pipeline context | Governance catalog: agents, tools, Guardrail profiles, models |
| Workstream execution | Team-owned cells | Unchanged. The portal has no surface here. |
| Assurance and operations | CloudWatch, CodePipeline and Registry consoles per account | Fleet inventory and health, access graph, effective policy, release evidence, traces |

## Operating-model rules it keeps

The portal is built to the rules the blueprint publishes, and the conformance suite (`tests/conformance/phase-27-agent-factory-portal.test.ts`) pins each one.

| Rule | How the portal keeps it |
| --- | --- |
| Capabilities are consumed through code, descriptors and pipelines, not administrator sessions | The portal shows state and evidence. It is not an administration console. |
| Workstream mutation is pipeline only | The portal creates no resource in a Workstream account and holds no mutating permission there. |
| Central visibility must not become central write access | The API role and the cell fleet reader role hold read actions only. Synthesis fails if a non-read action is added to the reader. |
| Tool Gateways use `AWS_IAM` in the default profile | The portal does not change any Gateway or Runtime authorizer. |
| Every denial has a positive twin | The role boundaries are asserted both ways in the conformance suite and exercised live before a release. |

## Architecture

```
 Platform account
   agent-factory-portal-edge (us-east-1)   CloudFront-scope web ACL, logged
   agent-factory-portal (platform Region)
     Amazon CloudFront + private Amazon S3     static web application, config.json
     Amazon Cognito user pool  or  Microsoft Entra ID   sign-in
     Amazon API Gateway HTTP API + JWT authorizer
     AWS Lambda (read-only API), role AgenticAI-PortalApi-<env>
        reads   AWS Agent Registry records, Guardrail profiles,
                Workload pipeline executions (release evidence)
        assumes AgenticAI-PortalFleetReader-<env> in each cell

 Workstream cell account (one per cell)
   agent-factory-portal-fleet-reader
     role AgenticAI-PortalFleetReader-<env>, read-only:
        AgentCore Runtime, Gateway, targets, Policy Engine and policies, Memory
        CloudWatch alarms and metrics
        Logs Insights over the spans log group
     trusts only AgenticAI-PortalApi-<env> of the Platform account, with an external id
```

The web application loads `config.json` at start, so one build serves every environment. Only `GET` routes exist on the API; a request with any other method has no route.

## Personas and roles

Sign-in groups map to portal roles. The role decides what a person may see; the first milestone has no action to authorize.

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

| Portal role | Registrar (create, change, submit, delete) | Approver (approve, reject) | Tenants |
| --- | --- | --- | --- |
| `platform` | yes | yes | every tenant |
| `developer` | yes | no | tenants of the user's groups |
| `approver`, `security` | no | yes | tenants of the user's groups |
| `sre`, `finops`, `readonly` | no | no | none |

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
| Approver function, role `AgenticAI-RegistryApprover-<env>` | Approves or rejects a submitted record. Cannot create or change one. The person who submitted a record cannot decide it, whatever their role. |
| Audit trail (DynamoDB, point-in-time recovery) | Every decision, allowed or refused, with who and why. The functions can append; none can change or delete an entry. |
| Rules of the registration core | An approved record cannot have its runtime, gateway, tool subscriptions, risk class or data classification changed; that needs a new registration. Any other change returns the record to draft for a new review. |

Where SCP-11 is attached, add the approver role to the protected authority manifest (purpose: registry), or its status decisions are denied by the organization.

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
| `agenticai/portalCells` | portal | Cells the portal reads (JSON array) |
| `agenticai/portalModelAllowlist`, `agenticai/portalGuardrailTag` | portal | Catalog inputs |
| `agenticai/portalApiCodePath`, `agenticai/portalWebDistPath` | portal | Override the bundle locations |
| `agenticai/portalLogsKeyArn`, `agenticai/portalEdgeLogsKeyArn` | portal, edge | Operator-provisioned customer managed key for the log groups (optional). The stacks never create or tag a key. |
| `agenticai/portalGovernedActions` | portal | `true` adds registration and approval (default: off, read-only) |
| `agenticai/portalAgentRegistryId`, `agenticai/portalAgentRegistryArn` | portal | The agent Registry (outputs of the agent-registry stage); required with governed actions |
| `agenticai/portalGroupTenantMap` | portal | Group or app-role name to the tenant ids its members may act for (JSON) |
| `agenticai/portalRegistryId`, `agenticai/portalRegistryArn` | portal | Use a given Platform Registry instead of the environment's default |
| `agenticai/portalRetainData` | portal | Retain the user pool and buckets on deletion (default: prod only) |
| `agenticai/portalCellAccountId`, `agenticai/portalExternalId`, `agenticai/portalSpansLogGroupNames` | fleet reader | Cell account, shared external id, span log groups |

## What the portal reads

| View | Source |
| --- | --- |
| Agents | Registry records with schema `agenticai.agent-governance/1.0`, merged with AgentCore Runtimes discovered in each cell. A Runtime with no record is shown as discovered, not registered. |
| Tool gateways | AgentCore Gateways of each cell, their targets, and the Registry tool records (`agenticai.tool-governance/1.0`) |
| Effective policy | The Gateway's AgentCore Policy Engine: Cedar text as deployed, and the mode (`OFF`, `LOG_ONLY`, `ENFORCE`) |
| Access graph | Owner group to agent, agent to Tool Gateway, with whether a policy engine is attached |
| Release evidence | Executions of the cell's Workload pipeline, including the evaluation gate result |
| Traces and metrics | CloudWatch Logs Insights over the cell's spans log group and CloudWatch metrics for the Runtime |
| Fleet health | CloudWatch alarms per cell: critical, needs attention, healthy, or no data |
| Guardrail profiles, models | Amazon Bedrock Guardrails in the Platform account and the configured model allow-list |

## Removal

Delete the stacks in reverse order: portal, fleet readers, edge, and last the agent Registry if its records are no longer needed. Use `scripts/agent_factory_portal_teardown.py` for the portal stack: its access-log bucket keeps receiving log deliveries for a while after the stack has emptied it, so a plain stack delete can fail on that bucket, and the log groups of the stack's provider functions are not stack resources. The script captures what the stack owns before deleting, retries after emptying exactly those buckets, and removes exactly those log groups.

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
| Platform control, governed actions | Registration and approval through the registration API, tool subscription requests, release approval with evidence beside it, policy change proposals as pull requests, on-demand replay of a positive call and its adversarial twin in nonproduction, incident containment through the cell's kill switch |
| Developer experience | Golden-path catalog with versions and support windows, onboarding intake that produces the descriptor and pull request, "my agents" with pipeline status |
| FinOps and product metrics | Cost by allocation tag, budgets, tag coverage, and the platform product metrics of README section 7 |
| Representative fleet and delegated access | A fleet of representative cells for canarying platform changes, and an optional implementation profile for per-user tool authorization |

## Provenance

The web application is derived from the Agentic Governance Platform (Apache-2.0) and is maintained independently here. See `apps/agent-factory-portal/NOTICE` and `apps/agent-factory-portal/THIRD_PARTY.md`.
