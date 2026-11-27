# Protected authority manifests

Role names are not an authorization boundary. The management deployment accepts
an owner-reviewed inventory and compiles the identity and authority protections
from it. It does not accept a claim such as `protectionAttached=true`.

Supply one of these management-stage context values:

- `agenticai/protectedAuthorityManifest`: the JSON object or its JSON encoding.
- `agenticai/protectedAuthorityManifestPath`: a local file containing that object.

Using both is an error. The resolved management stack account must match the
manifest. Gateway lockdown also requires the configured exact
`agenticai/gatewayAdminWorkloadAccountIds`; every account needs its explicitly
enrolled `gateway-admin` identity. Enabling Omni telemetry requires enrolled
`telemetry` identities. Legacy role-name or pattern options are rejected.
Without a manifest SCP-02 permits no member Mantle exception.

## Inventory contract

The TypeScript definitions in
`packages/organizations/src/protected-authority.ts` are the schema. Unknown
fields, wildcards, tokens, duplicate identities, missing references, cyclic
controller graphs and member-controlled authority roots are rejected.

| Record | Required evidence |
| --- | --- |
| Manifest | Schema version 1, exact organization and management account IDs, explicit trusted control accounts, governed accounts, and an approved inventory epoch. Trusted roots must be outside governed member accounts. |
| Role | Stable record ID, exact IAM role ARN and live RoleId, purposes, lifecycle and PassRole controllers, actual trust and inline-policy digests, all attached policies and boundary, protected policy records and execution consumers. |
| Policy | Exact customer-managed policy ARN, immutable PolicyId, approved default version and canonical document digest, and its controller chain. AWS-managed attachments are recorded by exact ARN. |
| Native Policy Engine | Kind `agentcore-policy-engine`, exact AgentCore engine ARN, approved complete configuration, policy-list and tag snapshot, permitted controllers, and protected owning stack and customer-managed encryption key. |
| Native Cedar policy | Kind `agentcore-policy`, exact `policy-engine/<engineId>/policy/<policyId>` ARN, approved full `GetPolicy` configuration and Cedar-definition digest, and its exact protected engine dependency with the same controllers. |
| Execution consumer | Exact Lambda, Gateway, stack, pipeline, build or state-machine ARN; actual execution role; approved configuration and code/template digests; permitted controllers and protected input dependencies. Gateway and Lambda records may also declare exact role-record `invokerIds`, separate from mutation controllers. |
| Trusted input | Exact bucket/object, image repository, key, parameter, secret, source connection or layer, approved document/configuration state, ownership and permitted writers. |

For a shared executor, include **every** consuming CloudFormation stack,
including imported, legacy and unrelated named stacks. Step Functions snapshots
also bind every published version and alias, including a version retaining an
earlier execution role. Include every privileged
Lambda consumer using its unqualified base ARN. Its configuration snapshot must
include every published version, alias, layer, resource policy, function URL
and event source that can execute protected authority. Qualified Lambda
consumer records are rejected. Protect
the real deployment inputs and their writers; protected input buckets centralize
writes across their entire object namespace, so include all legitimate writers; listing an arbitrary dummy asset
does not establish a complete live inventory.

SCP exceptions use separate denials for an unapproved `aws:PrincipalArn` and an
unapproved `aws:userid`. The session suffix is the only wildcard in the entity
gate. Protections for Lambda versions and scoped resource families do not
create principal-name exceptions. Recreation requires enrollment of the new
RoleId and a new approved inventory epoch.

Protected Gateways require `AWS_IAM` authorization. Their `InvokeGateway`
permissions are restricted to exact ARN and RoleId pairs declared in
`invokerIds`; omission restricts invocation to the resource controllers.
An ordinary IAM grant to another caller does not bypass this organization
guard. Declare approved application roles explicitly and include the Gateway
role in the interceptor Lambda's `invokerIds`. These invocation approvals do
not grant mutation, PassRole or direct access to other privileged targets.
A caller role with the sole purpose `gateway-invoker` may have no service
execution consumer, while retaining all trust, policy and lifecycle checks
and an unconditional PassRole denial. Any service execution role must still
declare its actual protected consumer and complete input graph.

The inference construct's existing default is `CUSTOM_JWT`; that mode cannot
be certified for a protected-role Gateway. Use the construct's
`authorizerType: 'AWS_IAM'` or platform-stage context
`agenticai/inferenceGatewayAuthorizerType=AWS_IAM`, and migrate approved callers
to SigV4 authentication. The Gateway retains its REQUEST guardrail interceptor
and inference target limits. Cognito resources retained by the construct do
not authorize requests to an IAM-mode Gateway. Reconciliation rejects JWT and
unauthenticated Gateways rather than assuming the IAM caller gate applies.

Native Policy Engine mode requires complete authority enrollment. Add its engine
and **every** child policy to the Gateway's protected dependency graph, including
policies in `LOG_ONLY` mode. The read-only verifier enumerates the full engine
policy list without a resource-scope filter and rejects missing, duplicate,
unexpected, inactive, unreadable or unmodeled records. It binds the engine's
actual customer-managed KMS key, tags, full policy definitions and the attached
Gateway's resource policy. Generated-policy references and Dogwood inputs remain
unsupported because their additional authority dependencies are not modeled.
The exact Cedar definition is owner-reviewed; a digest does not itself establish
that its authorization rules are appropriate.

SCP-09 fences policy and engine lifecycle, engine tags, `ManageAdminPolicy` and
`ManageResourceScopedPolicy` as well as Gateway mutation. Native policies are
CloudFormation-owned, so enroll their actual protected CloudFormation executor
as their controller. The business deny admits those exact controller ARN/RoleId
pairs alongside GatewayAdmin, while resource-specific authority guards restrict
them to the enrolled engines, policies and scoped Gateway authorization.
Gateway configuration and target mutation remain reserved to GatewayAdmin.
`CreatePolicyEngine` and `ManageAdminPolicy` authorize against `*`;
`ManageResourceScopedPolicy` authorizes against the Gateway ARN. Policy
update/deletion authorizes against both the engine and its nested policy ARN.
Review those service contexts in Sandbox before rollout.
The existing KMS grant checks remain in force: grant grantees and retiring
principals must be enrolled key controllers. An unsupported service-created
grant prevents reconciliation; no exception is inferred from its service
origin. Obtain the actual engine key/grant inventory and deployed controls
before promotion. SCP-09 also refuses a rendered business policy above the
5000-character compilation budget; review the exact controller scope rather
than deploying an oversized document.

## Read-only reconciliation

`scripts/verify-protected-authority.py` requires Python 3.10+, boto3 and PyYAML,
and reconciles an approved manifest against explicit AWS profiles. It reads state and refuses missing access, mismatched
identity/policy/configuration, undeclared consumers and incomplete installed
protections. It does not create roles, change policies, deploy stacks or
approve authority.

Prepare a JSON account-to-profile map and expected policy records from the
approved management assembly. Keep the files with the reviewed release:

```text
python scripts/verify-protected-authority.py \
  --manifest /approved/authority.json \
  --profile-map /approved/account-profiles.json \
  --expected-policies /approved/policy-expectations.json
```

Generate the expected records from the approved management template, resolving
its OU/root references with an explicit logical-ID-to-target-ID map:

```text
python scripts/render-protected-authority-expectations.py \
  --manifest /approved/authority.json \
  --template /approved/management.template.json \
  --target-map /approved/organization-targets.json > /approved/policy-expectations.json
```

This local generator reads JSON and does not approve the release.
Expected policy records bind the canonical manifest hash, policy names,
canonical content hashes and exact attachment targets. Obtain resolved OU IDs
from the installed management stack when the assembly uses CloudFormation
references. The verifier must inspect every enabled Region; regional API denies do not
prove old AWS service-triggered consumers are absent. Missing read access or
unsupported service inventory fails the check. Arrange centrally approved
read-only inventory access before tightening region controls, and verify
current SDK/service endpoint coverage. Do not treat skipped regions or
`AccessDenied` responses as empty inventory. Standard Step Functions saved
executions and active CodeBuild executions are checked as well as current
resource configuration. Express execution history cannot be fully enumerated
by these APIs: the verifier fails closed where that history could contain
protected authority. Saved Distributed Map child history is also unsupported
and rejected. Dedicated deployment authority and a centrally reviewed
cutover are required; a mocked verifier pass does not resolve that live gap.

AgentCore inventory covers other role-bearing consumer families as well as
Gateways; a protected role attached to an unsupported runtime, browser, code
interpreter or other consumer fails reconciliation. Pipeline history includes
saved execution pipeline versions and their top-level and action roles.
Active protected CloudFormation, Step Functions, pipeline and build executions
require a quiet, centrally controlled cutover; an approved current configuration
does not approve an older running execution's code or input. Protected-role
StackSets are unsupported because the per-target execution and recovery graph
is not bound by this manifest. Unrelated ordinary self-managed StackSets remain
outside the protected graph.
Pre-existing executable, in-progress or unresolved CloudFormation change sets
also fail reconciliation, including those on stacks whose current execution
role is ordinary. The change-set description cannot establish its retained
execution authority. Central owners must drain or remove those sets before
enrollment; future protected-role change-set creation is subject to the
controller and PassRole guards.

Protected CloudFormation templates must have verifiable executable inputs.
Macros, `Transform`/`Fn::Transform`, unsupported nested templates, and external
custom-resource providers are rejected. Supported custom-resource callbacks
must bind actual protected Lambda providers and their input dependencies.
Dynamic secret/SSM inputs require exact protected dependencies. Lambda EFS
code/input mounts are unsupported. An original-template digest alone cannot
establish immutability of these separately mutable inputs.

A successful check proves observed inventory and installed configuration at
that time; it is not a live attack or deployment test.
In particular, these APIs cannot prove the absence of all pre-enrollment queued
or active Lambda and service-triggered work. Central owners must establish a
clean execution and input cutover, drain that work, and run the deployed
positive and negative controls before granting protected exceptions.

## Supported build and pipeline inputs

Remote Git and webhook authority cannot be established by hashing a build
configuration. Protected builds require approved inline `NO_SOURCE`, an exact
protected S3 source, or a reconciled enrolled CodePipeline source. Their real
secondary inputs, output artifact stores and image dependencies must remain
inside the protected graph. Protected pipelines require supported S3/ECR
sources, enrolled build projects, and protected artifact buckets and keys.
Protected interactive CodeBuild sandboxes and batch execution are denied;
existing sandboxes, active builds, mixed batch roles, fleets and public-access
role consumers of protected authority require cleanup before enrollment.
Unsupported source providers, writers, mixed role overrides, and external
inputs fail reconciliation. Migrate them to a verifiable input path before
enrollment; the synthetic fixture is not a production deployment inventory.

## Enrollment and rollout

1. Central owners select the authority boundary and recovery path. Prefer a
   dedicated protected CDK qualifier and executors. If a shared executor is
   retained, enumerate and protect all consumers.
2. Bootstrap identities and resources in a controlled Sandbox window; tighten
   trusts, record actual RoleIds and policy/configuration digests, and review
   the complete controller and input graph.
3. Synthesize with the reviewed manifest. The management assembly installs
   direct account protections before OU business exceptions. Review the
   resulting per-account policies and account/OU quotas.
4. Reconcile installed policy content and targets with the approved assembly.
   Test lookalikes, recreation, IAM/trust/policy mutation, foreign PassRole,
   direct privileged Lambda invocation, stored-role stack/change-set reuse,
   and pipeline/build/input replacement. Run legitimate deployment and
   unrelated-resource controls through the same policies.
5. Promote the same approved configuration to Workloads only after Sandbox
   controls pass. Enroll new consumers before granting protected execution.
   Use centrally controlled management policy recovery for migration rather
   than introducing a new member-admin wildcard exception.

The PassRole protections require the approved destination service and resource
context. A missing destination context is denied. Validate those service
contexts in Sandbox before rollout; do not weaken the guard to make an
unexpected provider or legacy consumer pass.
