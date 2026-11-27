# Runtime canary routing

Generated workload promotion can use `agenticai/runtimeCanary`, an exact JSON
object with `aliasArn`, `baselineVersion`, `candidateVersion` and
`routingRoleArn`. The alias must be in the nonproduction workload account and
Region. Both versions must be published versions of the same Lambda router.
Supply optional `alarmName` to select the exact deployed composite health alarm;
omitting it retains the established online-evaluation alarm name.
Custom canary commands remain an alternative; they cannot be combined with this
managed controller. Missing routing configuration retains the fail-closed gate.

The `runtime-router` stage creates a service-only, IAM-invoked Lambda router with
a named AgentCore endpoint pinned to an exact runtime version. Configure
`routerRuntimeId`, `routerRuntimeVersion`, `routerSourceRevision`,
`routerFunctionName`, `routerRoutingRoleName` and `routerPipelineCanaryRoleArn`.
Also supply `routerHealthAlarmName` beginning with `agenticai-runtime-canary-`.
Bootstrap one router version. For a candidate deployment also supply the prior
`routerBaselineLambdaVersion` and `routerBaselineRuntimeVersion`, and preserve
the baseline's endpoint and published Lambda version. The candidate must target
a different published version of that same AgentCore runtime.

The router does not accept runtime targets or credentials from invocation
payloads. Only trusted service invokers should receive `lambda:InvokeFunction`;
the calling application must bind actor/session identity before invoking it.
This stage creates no public URL and is not an end-user authentication layer.
Track retained owned endpoints and versions in the deployment inventory.

The router's health alarm combines actual Lambda invocation failures, incomplete
agent responses, and inference first-token p99 above the existing 1500ms SLO.
It emits numeric CloudWatch metrics without prompts, actor IDs, sessions or
replies. Missing sampled completion or latency data blocks promotion. Keep real
traffic flowing during the soak; do not force alarm states to pass this gate.
These availability and latency checks complement the mandatory offline quality
evaluation; they do not replace correctness, refusal or tool-success scoring.

`runtime_canary.py` first verifies the baseline alias, both immutable Lambda
versions and their actual READY AgentCore endpoints. It applies a real weighted
alias using AWS revision preconditions. During the soak, the alias must remain
unchanged and the exact composite evaluation alarm must stay OK. Missing alarms,
INSUFFICIENT_DATA, ALARM and failures block promotion. A failed soak restores the
baseline only if the alias still matches this rollout; it never overwrites
another deployment. After a healthy soak it promotes the exact candidate
version. The default is 5 percent for 30 minutes. Supply `canaryPercent` and
`canarySoakMinutes` only for an explicitly bounded validation environment.

An alias readback alone is not full acceptance: invoke the routed service and
observe both actual runtime versions, prove guardrail/tool/memory behavior, run
the evaluation gate, and exercise an alarm-triggered rollback. Keep the
production manual approval and evaluation gates intact.
# Generated-agent deployments

Registry mode uses the same evaluation → approval → canary start → canary soak
sequence when `agenticai/runtimeCanary` is supplied. All evaluation and routing
steps consume the execution's source artifact, so their checked-in scripts are
available. A routing configuration requires the generated-agent evaluation
gate; a compatibility handshake cannot promote through this path.

`stage=workload-inference` creates a separately named JWT inference Gateway for
generated-agent M2M credentials. Supply `agenticai/envName`, `stackName`, `gatewayName`,
`applicationId`, `tenantId`, `agentId`, `costCentre`, `inferenceModelRateLimits`,
`guardrailIdentifier`, `guardrailVersion`, `guardrailArn`, and explicit
`m2mSecretReaderAccountIds`. It uses the mandatory server-side guardrail and
creates an encrypted M2M secret. Use distinct Gateway and stack names when a
protected IAM inference Gateway already serves existing clients. Any trusted
static system prompt requires a reviewed complete-prompt SHA-256 in
`trustedSystemPromptHashes`; untrusted prompts remain guarded.
The generated-agent service entrypoint requires a nonempty, bounded `prompt`
and an explicit opaque `actorId`. Trusted IAM callers must bind that value to
their authenticated application identity. Missing actors are refused before
token acquisition or Memory access. The router accepts its service envelope's
`actor_id` and forwards the agent's actual `actorId` field.

For a separate Workload deployment namespace, `agenticai/bootstrapQualifier`
selects an existing explicitly prepared CDK bootstrap and is carried into
pipeline synths. It does not rewrite another bootstrap. Deploy its service
roles, asset stores and execution policies independently, and review the
pipeline-account trust before allowing cross-account deployment.
