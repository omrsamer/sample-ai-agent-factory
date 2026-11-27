/**
 * Synthetic authority graph used by local SCP contract tests.
 *
 * These identifiers and digests are test fixtures, not an approved deployment
 * inventory. Each privileged consumer and its executable input is explicit.
 */
import type {
  ProtectedAuthorityManifest,
  ProtectedAuthorityResource,
  ProtectedAuthorityRole,
} from "../../packages/organizations/src/protected-authority";

const DOCUMENT_SHA256 = "a".repeat(64);
const CONFIGURATION_SHA256 = "b".repeat(64);
const CODE_SHA256 = Buffer.alloc(32).toString("base64");

export function authorityFixture(options: {
  managementAccountId?: string;
  governedAccountIds?: readonly string[];
  gatewayAdminAccountIds?: readonly string[];
  registryAccountIds?: readonly string[];
  region?: string;
} = {}): ProtectedAuthorityManifest {
  const managementAccountId = options.managementAccountId ?? "999999999999";
  const governedAccountIds = [...(options.governedAccountIds ?? [
    "222222222222",
    "333333333333",
    "444444444444",
  ])];
  const region = options.region ?? "us-west-2";
  const gatewayAdminAccounts = options.gatewayAdminAccountIds ?? governedAccountIds;
  const registryAccounts = options.registryAccountIds ?? ["222222222222"];
  const roleId = (index: number) => `AROA${String(index).padStart(17, "0")}`;
  const roles: ProtectedAuthorityRole[] = [{
    id: "central-owner",
    arn: "arn:aws:iam::111111111111:role/AgenticAI-GuardrailAdmin",
    roleId: roleId(1),
    purposes: ["controller", "guardrail-admin"],
    lifecycleControllerIds: [],
    policyResourceIds: [],
    consumerResourceIds: [],
    trustPolicySha256: DOCUMENT_SHA256,
    inlinePolicySha256: {},
    attachedPolicyArns: [],
  }];
  const resources: ProtectedAuthorityResource[] = [];

  for (const [index, account] of governedAccountIds.entries()) {
    const prefix = `cell-${account}`;
    const controller = `${prefix}-executor`;
    const gatewayAdmin = `${prefix}-gateway-admin`;
    const mantle = `${prefix}-mantle`;
    const policy = `${prefix}-policy`;
    const stack = `${prefix}-stack`;
    const provider = `${prefix}-provider`;
    const interceptor = `${prefix}-interceptor`;
    const gateway = `${prefix}-gateway`;
    const asset = `${prefix}-asset`;
    const bucket = `${prefix}-bucket`;
    const executorArn = `arn:aws:iam::${account}:role/cdk-protected-cfn-exec-role-${account}-${region}`;
    const gatewayAdminArn = `arn:aws:iam::${account}:role/AgenticAI-D03-nonprod-GatewayAdmin`;
    const mantleArn = `arn:aws:iam::${account}:role/AgenticAI-InferenceGateway-nonprod`;
    const policyArn = `arn:aws:iam::${account}:policy/ProtectedAuthorityFixture`;
    const baseRole = {
      lifecycleControllerIds: ["central-owner"],
      policyResourceIds: [policy],
      trustPolicySha256: DOCUMENT_SHA256,
      inlinePolicySha256: {},
      attachedPolicyArns: [policyArn],
      passRoleControllerIds: [controller],
    };
    roles.push(
      {
        ...baseRole,
        id: controller,
        arn: executorArn,
        roleId: roleId(index * 10 + 2),
        purposes: [
          "controller",
          "telemetry",
          ...(registryAccounts.includes(account) ? ["registry" as const] : []),
        ],
        consumerResourceIds: [stack, interceptor],
        passRoleControllerIds: ["central-owner"],
      },
      {
        ...baseRole,
        id: gatewayAdmin,
        arn: gatewayAdminArn,
        roleId: roleId(index * 10 + 3),
        purposes: gatewayAdminAccounts.includes(account)
          ? ["gateway-admin"]
          : ["controller"],
        consumerResourceIds: [provider],
      },
      {
        ...baseRole,
        id: mantle,
        arn: mantleArn,
        roleId: roleId(index * 10 + 4),
        purposes: ["mantle"],
        consumerResourceIds: [gateway],
      },
    );
    const baseResource = {
      controllerIds: [controller],
      dependsOnIds: [] as string[],
      configurationSha256: CONFIGURATION_SHA256,
    };
    resources.push(
      {
        id: policy,
        kind: "policy",
        arn: policyArn,
        controllerIds: ["central-owner"],
        dependsOnIds: [],
        documentSha256: DOCUMENT_SHA256,
        policyId: `ANPA${String(index + 1).padStart(17, "0")}`,
        defaultVersionId: "v1",
      },
      {
        ...baseResource,
        id: bucket,
        kind: "s3-bucket",
        arn: `arn:aws:s3:::authority-fixture-${account}`,
        accountId: account,
        controllerIds: ["central-owner"],
        documentSha256: DOCUMENT_SHA256,
      },
      {
        ...baseResource,
        id: asset,
        kind: "s3-object",
        arn: `arn:aws:s3:::authority-fixture-${account}/assets/runtime.zip`,
        accountId: account,
        controllerIds: ["central-owner"],
        dependsOnIds: [bucket],
        versionId: "approved-fixture-version",
      },
      {
        ...baseResource,
        id: stack,
        kind: "stack",
        arn: `arn:aws:cloudformation:${region}:${account}:stack/ProtectedAuthorityFixture/11111111-2222-4333-8444-555555555555`,
        dependsOnIds: [asset],
        documentSha256: DOCUMENT_SHA256,
        executionRoleArn: executorArn,
      },
      {
        ...baseResource,
        id: provider,
        kind: "lambda",
        arn: `arn:aws:lambda:${region}:${account}:function:authority-fixture-provider`,
        dependsOnIds: [stack, asset],
        codeSha256: CODE_SHA256,
        executionRoleArn: gatewayAdminArn,
      },
      {
        ...baseResource,
        id: interceptor,
        kind: "lambda",
        arn: `arn:aws:lambda:${region}:${account}:function:agenticai-inference-guardrail-nonprod`,
        dependsOnIds: [stack, asset],
        codeSha256: CODE_SHA256,
        executionRoleArn: executorArn,
      },
      {
        ...baseResource,
        id: gateway,
        kind: "gateway",
        arn: `arn:aws:bedrock-agentcore:${region}:${account}:gateway/authority-fixture-gateway`,
        dependsOnIds: [interceptor, stack, asset],
        executionRoleArn: mantleArn,
      },
    );
  }
  return {
    schemaVersion: 1,
    organizationId: "o-abc123def4",
    managementAccountId,
    trustedControlAccountIds: ["111111111111"],
    governedAccountIds,
    epoch: "fixture-1",
    roles,
    resources,
  };
}

export function fixtureRoles(
  purpose: ProtectedAuthorityRole["purposes"][number],
  manifest = authorityFixture(),
): ProtectedAuthorityRole[] {
  return manifest.roles.filter((role) => role.purposes.includes(purpose));
}
