import { App } from "aws-cdk-lib";
import { Template } from "aws-cdk-lib/assertions";

import {
  D03PlatformCoreStack,
  type D03TenantAllocation,
} from "../../apps/platform-account/lib/d03-platform-core-stack";
import { D03WorkloadAgentStack } from "../../apps/workload-account/lib/d03-workload-agent-stack";

const PLATFORM = "111111111111";
const ALPHA_ACCOUNT = "222222222222";
const BETA_ACCOUNT = "333333333333";
const runtimeArn = (account: string, tenant: string) =>
  `arn:aws:iam::${account}:role/AgenticAI-D03-${tenant}-primary-runtime`;
const allocations: D03TenantAllocation[] = [
  {
    tenantId: "alpha",
    agentId: "primary",
    workloadAccountId: ALPHA_ACCOUNT,
    costCentre: "a",
    envName: "nonprod",
  },
  {
    tenantId: "beta",
    agentId: "primary",
    workloadAccountId: BETA_ACCOUNT,
    costCentre: "b",
    envName: "nonprod",
  },
];

function synth(
  tenants: readonly D03TenantAllocation[] = allocations,
): Template {
  return Template.fromStack(
    new D03PlatformCoreStack(new App(), "TenantBoundaries", {
      env: { account: PLATFORM, region: "us-west-2" },
      workloadAccountIds: [ALPHA_ACCOUNT, BETA_ACCOUNT],
      externalId: "test-external-id",
      tenantAllocations: tenants,
    }),
  );
}

function resolveArn(value: any): string {
  if (typeof value === "string") return value;
  const join = value?.["Fn::Join"];
  if (!join) throw new Error(`Unexpected ARN token: ${JSON.stringify(value)}`);
  return join[1]
    .map((part: any) => {
      if (typeof part === "string") return part;
      if (part?.Ref === "AWS::Partition") return "aws";
      throw new Error(`Unexpected ARN token: ${JSON.stringify(part)}`);
    })
    .join(join[0]);
}

// Evaluate only the resource-policy authorization slice under test. Assume a
// malicious member administrator grants every action in the caller's identity
// policy. Unsupported conditions fail the test instead of being ignored.
function resourceAllows(
  statements: any[],
  action: string,
  account: string,
  principalArn: string,
  keys?: string[],
): boolean {
  return statements.some((statement) => {
    if (statement.Effect !== "Allow") return false;
    const actions: string[] = Array.isArray(statement.Action)
      ? statement.Action
      : [statement.Action];
    if (!actions.includes(action)) return false;
    const principals: string[] = Array.isArray(statement.Principal?.AWS)
      ? statement.Principal.AWS
      : [statement.Principal?.AWS];
    if (!principals.map(resolveArn).includes(`arn:aws:iam::${account}:root`))
      return false;
    return Object.entries(statement.Condition ?? {}).every(
      ([operator, values]) =>
        Object.entries(values as Record<string, unknown>).every(
          ([key, expected]) => {
            if (operator === "ArnEquals" && key === "aws:PrincipalArn")
              return expected === principalArn;
            if (
              operator === "ForAllValues:StringEquals" &&
              key === "dynamodb:LeadingKeys"
            ) {
              return (keys ?? []).every((value) =>
                (expected as string[]).includes(value),
              );
            }
            if (operator === "Null" && key === "dynamodb:LeadingKeys") {
              return (
                String(keys === undefined || keys.length === 0) === expected
              );
            }
            throw new Error(`Unexpected policy condition: ${operator}/${key}`);
          },
        ),
    );
  });
}

describe("Legacy D03 — per-allocation Bedrock authority", () => {
  const template = synth();
  const roles = template.findResources("AWS::IAM::Role");
  const policies = Object.values(template.findResources("AWS::IAM::Policy"));
  const profiles = template.findResources(
    "AWS::Bedrock::ApplicationInferenceProfile",
  );

  it("creates separate caller roles, and retires the shared role and export", () => {
    const names = Object.values(roles).map((role) => role.Properties.RoleName);
    expect(names).toContain("AgenticAI-D03-alpha-primary-BedrockCaller");
    expect(names).toContain("AgenticAI-D03-beta-primary-BedrockCaller");
    expect(names).not.toContain("AgenticAI-D03-BedrockCaller");
    expect(JSON.stringify(template.toJSON().Outputs)).not.toContain(
      '"AgenticAI-D03-BedrockCallerRoleArn"',
    );
  });

  it.each(allocations)(
    "binds $tenantId to its exact runtime and only its own application profile",
    (alloc) => {
      const [roleId, role] = Object.entries(roles).find(
        ([, resource]) =>
          resource.Properties.RoleName ===
          `AgenticAI-D03-${alloc.tenantId}-primary-BedrockCaller`,
      )!;
      const trust = role.Properties.AssumeRolePolicyDocument.Statement;
      expect(trust).toHaveLength(1);
      expect(resolveArn(trust[0].Principal.AWS)).toBe(
        `arn:aws:iam::${alloc.workloadAccountId}:root`,
      );
      expect(trust[0].Condition.ArnEquals["aws:PrincipalArn"]).toBe(
        runtimeArn(alloc.workloadAccountId, alloc.tenantId),
      );
      expect(trust[0].Condition.StringEquals["sts:ExternalId"]).toBe(
        "test-external-id",
      );
      expect(JSON.stringify(trust)).not.toContain("AgenticAI-D03-*-runtime");
      const policy = policies.find((resource) =>
        resource.Properties.Roles.some((ref: any) => ref.Ref === roleId),
      )!;
      const statements = policy.Properties.PolicyDocument.Statement;
      const invoke = statements.find(
        (statement: any) => statement.Sid === "AllowInvokeAllocatedBedrock",
      );
      const ownProfileId = Object.entries(profiles).find(
        ([, resource]) =>
          resource.Properties.InferenceProfileName ===
          `agenticai-d03-nonprod-${alloc.tenantId}-primary`,
      )![0];
      const foreignProfileId = Object.keys(profiles).find(
        (id) => id !== ownProfileId,
      )!;
      expect(invoke.Resource).toContainEqual({
        "Fn::GetAtt": [ownProfileId, "InferenceProfileArn"],
      });
      expect(invoke.Resource).not.toContainEqual({
        "Fn::GetAtt": [foreignProfileId, "InferenceProfileArn"],
      });
      expect(invoke.Condition.ArnEquals["bedrock:InferenceProfileArn"]).toEqual(
        { "Fn::GetAtt": [ownProfileId, "InferenceProfileArn"] },
      );
      expect(JSON.stringify(invoke.Resource)).not.toContain(
        "application-inference-profile/*",
      );
      expect(
        statements.find(
          (statement: any) =>
            statement.Sid === "DenyInferenceWithMissingGuardrail",
        ).Condition.Null["bedrock:GuardrailIdentifier"],
      ).toBe("true");
      expect(
        statements.find(
          (statement: any) =>
            statement.Sid === "DenyInferenceWithWrongGuardrail",
        ),
      ).toBeDefined();
      expect(
        statements.find(
          (statement: any) => statement.Sid === "AllowBaselineGuardrail",
        ).Action,
      ).toBe("bedrock:ApplyGuardrail");
    },
  );

  it("updates the workload caller to the same bounded role", () => {
    const workload = Template.fromStack(
      new D03WorkloadAgentStack(new App(), "AlphaWorkload", {
        env: { account: ALPHA_ACCOUNT, region: "us-west-2" },
        platformAccountId: PLATFORM,
        externalId: "test-external-id",
        tenantId: "alpha",
        agentId: "primary",
      }),
    );
    const statements = Object.values(
      workload.findResources("AWS::IAM::Policy"),
    ).flatMap((policy) => policy.Properties.PolicyDocument.Statement);
    expect(
      statements.find(
        (statement: any) => statement.Sid === "AssumePlatformBedrockCaller",
      ).Resource,
    ).toBe(
      `arn:aws:iam::${PLATFORM}:role/AgenticAI-D03-alpha-primary-BedrockCaller`,
    );
  });

  it("fails closed on foreign accounts and allocation names that alias one IAM role", () => {
    expect(() =>
      synth([{ ...allocations[0], workloadAccountId: "444444444444" }]),
    ).toThrow(/configured workloadAccountId/);
    expect(() =>
      synth([
        { ...allocations[0], tenantId: "a-b", agentId: "c" },
        { ...allocations[1], tenantId: "a", agentId: "b-c" },
      ]),
    ).toThrow(/distinct tenant\/agent role names/);
    expect(() => synth([{ ...allocations[0], tenantId: "*" }])).toThrow(
      /alphanumerics/,
    );
  });
});

describe("Legacy D03 — platform-enforced DynamoDB allocation", () => {
  const template = synth();
  const tables = Object.values(template.findResources("AWS::DynamoDB::Table"));

  it.each(tables.map((table) => [table.Properties.TableName, table]))(
    "%s allows legitimate tenant reads but refuses a member admin granting foreign reads",
    (_name, table) => {
      const statements =
        table.Properties.ResourcePolicy.PolicyDocument.Statement;
      expect(
        resourceAllows(
          statements,
          "dynamodb:GetItem",
          ALPHA_ACCOUNT,
          runtimeArn(ALPHA_ACCOUNT, "alpha"),
          ["alpha"],
        ),
      ).toBe(true);
      expect(
        resourceAllows(
          statements,
          "dynamodb:Query",
          BETA_ACCOUNT,
          runtimeArn(BETA_ACCOUNT, "beta"),
          ["beta"],
        ),
      ).toBe(true);
      expect(
        resourceAllows(
          statements,
          "dynamodb:GetItem",
          ALPHA_ACCOUNT,
          runtimeArn(ALPHA_ACCOUNT, "alpha"),
          ["beta"],
        ),
      ).toBe(false);
      expect(
        resourceAllows(
          statements,
          "dynamodb:Query",
          ALPHA_ACCOUNT,
          runtimeArn(ALPHA_ACCOUNT, "alpha"),
          ["alpha", "beta"],
        ),
      ).toBe(false);
      expect(
        resourceAllows(
          statements,
          "dynamodb:GetItem",
          ALPHA_ACCOUNT,
          runtimeArn(ALPHA_ACCOUNT, "beta"),
          ["beta"],
        ),
      ).toBe(false);
      expect(
        resourceAllows(
          statements,
          "dynamodb:GetItem",
          ALPHA_ACCOUNT,
          `arn:aws:iam::${ALPHA_ACCOUNT}:role/MemberAdmin`,
          ["alpha"],
        ),
      ).toBe(false);
      expect(
        resourceAllows(
          statements,
          "dynamodb:Query",
          ALPHA_ACCOUNT,
          runtimeArn(ALPHA_ACCOUNT, "alpha"),
        ),
      ).toBe(false);
      expect(
        resourceAllows(
          statements,
          "dynamodb:Query",
          ALPHA_ACCOUNT,
          runtimeArn(ALPHA_ACCOUNT, "alpha"),
          [],
        ),
      ).toBe(false);
      expect(
        resourceAllows(
          statements,
          "dynamodb:Scan",
          ALPHA_ACCOUNT,
          runtimeArn(ALPHA_ACCOUNT, "alpha"),
        ),
      ).toBe(false);
    },
  );

  it("permits own experiment writes and denies writes to another tenant or a registry", () => {
    for (const table of tables) {
      const statements =
        table.Properties.ResourcePolicy.PolicyDocument.Statement;
      const experiment =
        table.Properties.TableName === "agenticai-d03-experiment-tracking";
      expect(
        resourceAllows(
          statements,
          "dynamodb:PutItem",
          ALPHA_ACCOUNT,
          runtimeArn(ALPHA_ACCOUNT, "alpha"),
          ["alpha"],
        ),
      ).toBe(experiment);
      expect(
        resourceAllows(
          statements,
          "dynamodb:UpdateItem",
          ALPHA_ACCOUNT,
          runtimeArn(ALPHA_ACCOUNT, "alpha"),
          ["beta"],
        ),
      ).toBe(false);
    }
  });

  it("binds every cross-account registry-key grant to an allocated role through DynamoDB", () => {
    const key = Object.values(template.findResources("AWS::KMS::Key")).find(
      (resource) =>
        resource.Properties.Description ===
        "Platform-shared registry + experiment-tracking CMK.",
    )!;
    const grants = key.Properties.KeyPolicy.Statement.filter(
      (statement: any) =>
        String(JSON.stringify(statement.Principal?.AWS)).includes(
          ALPHA_ACCOUNT,
        ) ||
        String(JSON.stringify(statement.Principal?.AWS)).includes(BETA_ACCOUNT),
    );
    expect(grants).toHaveLength(2);
    for (const [index, grant] of grants.entries()) {
      const alloc = allocations[index];
      expect(grant.Condition.ArnEquals["aws:PrincipalArn"]).toBe(
        runtimeArn(alloc.workloadAccountId, alloc.tenantId),
      );
      expect(grant.Condition.StringEquals["kms:CallerAccount"]).toBe(
        alloc.workloadAccountId,
      );
      expect(grant.Condition.StringEquals["kms:ViaService"]).toEqual([
        "dynamodb.us-west-2.amazonaws.com",
      ]);
      expect(grant.Action).toContain("kms:GenerateDataKey");
    }
  });
});
