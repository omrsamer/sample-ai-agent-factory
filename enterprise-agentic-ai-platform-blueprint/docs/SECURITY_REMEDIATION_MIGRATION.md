# Security remediation migration

These changes address the 2026-11-25 source review. Offline tests verify the
request handling and synthesized policy contracts. They do not establish the
state of any deployed account or replace the deployment twins described below.

## Management Gateway lockdown

Set `agenticai/gatewayAdminWorkloadAccountIds` to a JSON array of exact,
12-digit Workstream account ID strings. The Management stage passes this list
through `OrgStack` to SCP-09, which attaches to the same OU targets as the other
policies. `agenticai/attachScpsToWorkloadsOu` accepts boolean values or the CLI
strings `true` and `false`; other values fail synthesis.

Workloads promotion now fails if the account list is empty. Sandbox-only
bootstrap retains its existing opt-in account list and warning when SCP-09 is
omitted. Supply the list for the Sandbox denial soak before promotion. Adding
SCP-09 consumes a policy slot: the existing synth quota gate still rejects
combinations exceeding nine custom policies plus FullAWSAccess. A deployment
using the full VPC set and Omni lockdown needs a reviewed policy consolidation.

After deployment, prove an ordinary member administrator cannot create a
Gateway or replace its interceptor/targets, and that the authorized Gateway
provisioner can deploy the intended configuration. SCP-09 also requires an
approved protected authority manifest; exact exception identity and enrollment
protections are described below.

## Inference interceptor prompts

The interceptor evaluates text from all client-provided roles, including
`system`, `developer`, and `assistant`, and from top-level `system` and
`instructions`. A role label no longer establishes trusted provenance.
Function-call arguments, tool results, and client-provided tool/function
descriptions and schemas also receive evaluation.

Protocol prompts can trigger the baseline prompt-attack classifier. If a
reviewed static system/developer prompt must be exempt, compute the SHA-256
digest of its exact UTF-8 text and configure
`agenticai/trustedSystemPromptHashes` with a JSON array of those lowercase
64-character digests. This is operator-owned configuration, limited to 32
digests and empty by default. Approve the full prompt from a reviewed build;
never populate the list from a request. Multipart prompts hash the joined text
parts with a newline between parts.

The generated agent's protocol depends on its subscribed tools. Inventory
every approved complete prompt before rollout; a catalogue or protocol change
requires a newly reviewed digest. Appending text changes the digest and forces
evaluation. The same text in user, tool, assistant, bare input, or prompt fields
remains evaluated. Configure no exemption when static provenance cannot be
established.

Exercise the deployed guardrail with the approved protocol and a benign user
turn, malicious system/developer/assistant turns, modified approved prompts,
tool results, and Anthropic/Responses request shapes. Confirm the legitimate
agent completes its tool loop and each blocked input stops before inference.
Offline tests use a fake Bedrock classifier and cannot prove live classification.

## Legacy D-03 allocations

The legacy `d03-platform` stack replaces its shared Bedrock caller with
`AgenticAI-D03-<tenant>-<agent>-BedrockCaller` for each declared allocation.
Its trust allows exactly that allocation's runtime role in its configured
account and still requires the ExternalId. Its invoke grant names only that
allocation's application inference profile and requires
`bedrock:InferenceProfileArn` to identify that profile. Direct raw-model and
system-profile calls no longer provide an alternative attribution path.

`bedrockCallerRoles` replaces the shared `bedrockCallerRole` construct property.
The old `AgenticAI-D03-BedrockCallerRoleArn` export is retired; exports are now
`AgenticAI-D03-BedrockCallerRoleArn-<tenant>-<agent>`. Workload and integration
callers use the allocation's new role name.

Registry and experiment resource policies also use declared allocations. They
require the exact allocated runtime ARN and its tenant partition key on the
Platform side. Missing partition-key context and scans are refused.
`GetItem`/`Query` reads and `PutItem`/`UpdateItem` experiment writes remain
available for the correct tenant. Registry KMS grants require the same runtime,
its account, and delegation through DynamoDB. A member administrator adding a
broad identity policy cannot expand this Platform-owned delegation.

Declare every authorized tenant/agent/account in
`agenticai/d03TenantAllocations`. The default remains only `demo/primary` in the
first configured workload account; other listed accounts no longer receive
blanket registry or Bedrock authority. Duplicate or aliasing role names and
allocations outside the configured account list fail synthesis.

For an existing deployment, schedule a maintenance window: pause legacy
workloads, inventory and migrate consumers of the retired export, deploy the
Platform roles/resource policies, update Workload roles and application callers,
then resume only after the positive and negative deployment twins pass.
CloudFormation will refuse removal of an export that still has importers.
Platform and Workload updates are separate account deployments; this source
change does not provide an uninterrupted rolling migration.

Use two real allocations to verify own-profile invocation succeeds with the
baseline guardrail, foreign-profile and direct-model invocation are denied,
own registry reads/experiment writes succeed, and foreign rows/roles are denied
even after the test member administrator grants a broad identity policy.
These cloud operations have not been performed as part of the offline fix.

## Protected SCP exemption authority

SCP-02, SCP-09, SCP-11 and SCP-13 no longer derive privileged exceptions from
role-name patterns. Exceptions require an explicit `ProtectedAuthorityManifest`
containing exact role ARNs, live RoleIds, centrally controlled lifecycle
authorities, managed-policy records, execution consumers and deployment inputs.
Independent ARN and entity denials prevent lookalikes and same-name recreation
from inheriting an exception. SCP-05 uses the same entity binding when that
manifest is supplied.

The management assembly compiles protections for the declared authority chain
and attaches them directly to each governed account before installing business
exceptions. Protections cover role and policy mutation, assumption and
PassRole, privileged Lambda mutation and invocation, existing CloudFormation
stacks that retain an execution role, and pipeline/build/asset configuration.
Read operations and unrelated ordinary resources remain outside those scoped
protections. Missing or incomplete configuration, insecure legacy options, an
unresolved management account, and exceeded policy size or attachment quotas
refuse synthesis.

Follow [Protected authority manifests](PROTECTED_AUTHORITY_MANIFEST.md) for
the schema and read-only AWS reconciliation. Existing customers must inventory
every actual consumer, including stacks outside the blueprint naming convention
that share a bootstrap executor. Prefer dedicated protected deployment roles.
Do not copy synthetic test RoleIds into deployment configuration.

Bootstrap and enroll the identities, consumers and assets before attaching
protection, using centrally controlled management recovery. Verify installed
policy hashes and repeat both attack and legitimate deployment twins in
Sandbox before Workloads promotion. Those live cloud operations are separate
operator acceptance; local source tests do not certify a customer's installed
organization policy.
