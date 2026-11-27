# Owned identity broker foundation

The generated runtime's identity provisioner invokes one reviewed, published broker version. Its purpose boundary explicitly denies direct AgentCore, Secrets Manager and KMS authority. The new broker owns Create, Update and Delete of its allocation's provider and workload identities. It reads an immutable Platform secret version internally; the source invocation, ownership ledger and logs never contain the client secret or tokens.

The foundation is a separate Root-owned step before the workload pipeline. It adds six resources: a broker purpose boundary, one Lambda execution role, one retained ownership ledger, one retained log group, one function and one published version. Existing CloudFormation executor policies are not changed by this specification. Use normal AWS authentication for the reviewed deployment supervisor; this repository has no credential CSV requirement.

## Render the foundation

Prepare a reviewed public JSON input with exactly `allocation` and `oauth`. Obtain the exact source secret ARN, immutable version, customer KMS key ARN and public OAuth fields from owned native evidence. Do not include `clientSecret`. `allocation` contains account, region, stage, six owner tags and the exact derived names and ARNs. `foundation_spec.allocation(...)` derives those fields from an explicit account, stage, secret binding and six owner tags. Tenant/agent hyphens remain in tags and Lambda names; AgentCore child names normalize hyphens to underscores, matching the generated runtime.

```sh
python3 scripts/owned-identity-broker/render_foundation.py \
  --input reviewed-public-allocation.json \
  --output reviewed-broker-foundation
```

This command only renders files and a deterministic code ZIP. It refuses an existing output directory and invented or inconsistent names, endpoints and versions. The rendered config file has canonical bytes. Supply those exact bytes and `brokerConfigSha256` as the function's configuration. The ZIP hash is not an AWS version or deployment receipt.

Before any upload or change set, an independent review must bind the full input, code ZIP, policy and template bytes. The native supervisor must verify caller/account/region, current stack and parameters, and fresh absence of every deterministic new resource name. Preserve unknown attempts and use one SDK attempt with durable exclusive intents, immutable root release pins and expiry checks immediately before each dispatch. The original, processed and three change-set read modes must agree on exactly six additions. Execution and native readback require separate review and releases.

The native parameters are `CodeBucket`, `CodeKey`, the actual returned `CodeVersion`, exact base64 `CodeSha256`, `BrokerConfigJson` and `BrokerConfigSha256`. The supervisor must verify the exact owned S3 version's bytes, owner, encryption and tags, then verify the actual role ID, purpose boundary/default, sole granular inline policy, retained table configuration, log, function revision/config/code and published version. No guessed version, `$LATEST` or alias is permitted.

## Bind the source

After the foundation has closed native proof, replace `ActualPublishedBrokerVersionArn` in the reviewed source boundary with the actual numeric qualified version ARN and preserve its own-log allow and explicit direct-authority deny. Review this boundary change separately. Apply the exact minimal Platform secret resource-policy and customer KMS policy grants for the new broker role; preserve every existing statement. A positive broker read is still a separate native acceptance requirement.

Supply the source CDK context:

```text
agenticai/identityProvisionerBrokerByAllocation = {
  "<account>:<region>:<stage>:<tenant>:<agent>": {
    "versionArn": "<actual reviewed numeric qualified broker version ARN>",
    "configSha256": "<hash of the exact published broker configuration>"
  }
}
```

The source refuses a missing binding, aliases, another allocation or account, and an unreviewed provisioner boundary. Run the canonical pinned local checks and actual version-bound strict synthesis. Independently review the resulting source archive and template deltas before native source publication, pipeline update or execution. A fixture's synthetic numeric version used in unit tests is never a deployment input.

## Legacy resources and ownership

Fresh preflight must check the deterministic source role name as well as source stack and function. Stack absence does not prove role, provider, identity, broker or ledger absence. If an older source function already exists, bind its original template, physical ID, role ID, complete configuration and code. Introducing the deterministic function name may replace that old function. Hold the update until a separately reviewed old-resource teardown or ownership path closes; never depend on a failing CloudFormation Delete to discover the conflict.

Name, ARN, tags, caller receipts or caller-writable logs cannot authorize adoption. Only the broker's durably acknowledged native HTTP 201 creator receipt and exact live child/tags/managed-secret checks confer ownership. A changed broker configuration, foreign stack, pending state, ambiguous response or lost conditional write holds further lifecycle actions. The ledger has no TTL, scan or delete route.

The broker reserves the fixed provider and request-derived identity conditionally, and verifies each exact name is absent, before either Create call. An active provider or an unresolved allocation intent blocks another request before it can create additional identities.

A new CloudFormation Create generation can reuse a provider only after the prior owned generation closed `DELETED_ABSENT`, the exact child and old managed secret are freshly absent, and an immutable archive of the old creator receipt is acknowledged before an exact conditional generation handoff. The old request's saved response never deletes or recreates the new generation. Unknown or incomplete generations cannot reset or migrate.

## Native acceptance and residual authority

Create atomically supplies the six fixed owner tags for both children. The code has no direct TagResource dispatch and never targets a parent. It persists its own HTTP 201 receipt before checking live identity, provider, tags and managed-secret ARN. There is no tagless fallback or retry. Actual atomic tagged Create behavior, service propagation, both child lifecycles, source-role immutable Invoke, exact secret read, all-account OAuth positives and paired negatives, and protected parent readbacks require fresh native tests of this chain.

The isolated broker's IAM policy necessarily includes exact default parent TagResource authority for the service's observed authorization requirement. A compromised broker role could technically tag those parents with the six allowed values. IAM does not provide a documented condition separating a requested child target from an authorization parent. The smaller managed purpose ceiling intersects the role's sole detailed inline policy; it is not a stand-alone equivalent of that detailed policy. Native preflight and readback must enforce zero additional policies or attachments.

Root-owned native tests must wait at least 360 seconds after the actual policy/function publication prerequisite. Full OAuth and all six registry alias permissions remain required before final workload acceptance. Registry roles must first exist and be verified before granting their exact permissions; GatewayPermissionReady must close before target registration. Do not infer readiness or continuity of a future role ID from a temporary fixture.
