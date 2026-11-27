# Deploying a local source snapshot

The normal pipeline source remains the configured GitHub repository and its
`main` branch. To test local fixes before publishing them, both pipeline stacks
also accept a private S3 source archive:

```text
agenticai/sourceBucketName=<versioned-source-bucket>
agenticai/sourceObjectKey=sources/<archive-sha256>.zip
```

Supply both values together. The archive must contain the Blueprint package at
its root or under `enterprise-agentic-ai-platform-blueprint/`. Include the
lockfile, source files, tests, and required assets; exclude credentials,
environment files, dependency installations, and generated cloud assemblies.

Create the source bucket in the pipeline account and Region with versioning,
encryption, public access blocking, and an HTTPS-only policy. Verify its account
owner before uploading. Use a new digest-specific key for each reviewed
snapshot, record the returned object version, and verify the archive checksum.
Start the pipeline with that source object's version as a
`S3_OBJECT_VERSION_ID` source revision override. S3 polling is disabled, so a
later upload does not automatically promote code.

The selected bucket and key are carried into the pipeline's synth context,
keeping self-mutation on the same snapshot. Omitting both S3 settings restores
the normal GitHub configuration, which still requires the repository and
CodeConnections ARN. GitHub publishing is a separate action.

GA Registry Workload pipelines preserve the full Git commit SHA contract for
GitHub sources. A local S3 source instead requires the exact key
`sources/<64-character-sha256>.zip` and a concrete pipeline owner account.
Before resolving either environment's Registry context, the synth verifies the
exact immutable object version, expected bucket owner, archive checksum and
every extracted source entry. Missing, changed, duplicate, linked or unsafe
archive entries fail synthesis. The resolver emits schema version 2.0 with a
typed `sourceArchive` and `s3-sha256:<digest>` revision; it never substitutes an
object version for a Git SHA. GitHub contexts retain schema version 1.0.

The Platform pipeline also forwards `agenticai/inferenceGatewayAuthorizerType`
and `agenticai/trustedSystemPromptHashes` into both deployment stages. The
default authorizer remains `CUSTOM_JWT`; an `AWS_IAM` deployment needs its
reviewed caller resource policy before cross-account inference acceptance.

For a development test, `agenticai/regulated=false` disables the optional NIST
aspect and is preserved through pipeline synthesis. AWS Solutions checks and
strict synthesis remain enabled. This setting does not establish production
certification. The production approval and workload evaluation/canary gates
remain in place.

For an isolated test bootstrap, set `agenticai/bootstrapQualifier` to the new
qualifier and supply both `agenticai/workloadRoleBoundaryName` and
`agenticai/pipelineRoleBoundaryName`. Pipeline service roles receive the pipeline
boundary; nested workload stages receive the application boundary. The latter
must not allow bootstrap role assumption or IAM policy administration. Create
and review the isolated bootstrap before deployment. These contexts do not
modify an existing shared `CDKToolkit`.
