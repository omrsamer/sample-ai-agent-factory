import { App } from "aws-cdk-lib";
import { Template } from "aws-cdk-lib/assertions";
import { RegistryStack } from "../../apps/platform-account/lib/registry-stack";

const stack = new RegistryStack(new App(), "Registry-Approval-Test", {
  env: { account: "222222222222", region: "eu-west-1" },
  envName: "nonprod",
  workloadAccountIds: ["333333333333"],
  registrySynthAccountId: "222222222222",
  grantGatewayInvokePermissions: false,
  gatewayWorkloadAccountId: "333333333333",
  applicationId: "platform-registry",
  agentId: "shared",
  tenantId: "shared",
  costCentre: "platform",
});
const template = Template.fromStack(stack);

test("each producer record has a version/content/provenance-bound approval hook before publication", () => {
  const records = template.findResources("AWS::AgentRegistry::RegistryRecord");
  const approvals = template.findResources(
    "Custom::AgenticAIGaRegistryApproval",
  );
  expect(Object.keys(approvals)).toHaveLength(2);
  const parameters = Object.values(
    template.findResources("AWS::SSM::Parameter"),
  );
  for (const [id, record] of Object.entries(records)) {
    const name = record.Properties.Name;
    const [approvalId, approval] = Object.entries(approvals).find(
      ([, resource]) => resource.Properties.RecordName === name,
    )!;
    expect(approval.Properties).toMatchObject({
      AccountId: "222222222222",
      RecordId: { "Fn::GetAtt": [id, "RecordId"] },
      RecordArn: { "Fn::GetAtt": [id, "RecordArn"] },
      RecordVersion: record.Properties.RecordVersion,
      DescriptorData: record.Properties.Descriptors.Custom.Data,
      Tags: {
        "aws:cloudformation:logical-id": id,
        "aws:cloudformation:stack-id": { Ref: "AWS::StackId" },
        "aws:cloudformation:stack-name": { Ref: "AWS::StackName" },
      },
    });
    expect(approval.DependsOn).toContain(id);
    const pointer = parameters.find((parameter) =>
      parameter.Properties.Name.endsWith(`/records/${name}/id`),
    )!;
    expect(pointer.Properties.Value).toEqual({
      "Fn::GetAtt": [approvalId, "RecordId"],
    });
    expect(record.DeletionPolicy).toBe("RetainExceptOnCreate");
    expect(record.UpdateReplacePolicy).toBe("Retain");
  }
});

test("approval IAM has only exact parent metadata and exact native record submission access", () => {
  const recordIds = Object.keys(
    template.findResources("AWS::AgentRegistry::RegistryRecord"),
  ).sort();
  const registryId = Object.keys(
    template.findResources("AWS::AgentRegistry::Registry"),
  )[0];
  const policy = Object.values(template.findResources("AWS::IAM::Policy")).find(
    (resource) =>
      JSON.stringify(resource.Properties.PolicyDocument).includes(
        "agent-registry:SubmitRegistryRecordForApproval",
      ),
  )!;
  expect(policy).toBeDefined();
  const statements = policy.Properties.PolicyDocument.Statement as Array<{
    Action: string | string[];
    Resource: unknown;
  }>;
  const registryStatements = statements.filter((statement) =>
    JSON.stringify(statement.Action).includes("agent-registry:"),
  );
  expect(registryStatements).toHaveLength(2);
  expect(registryStatements[0]).toMatchObject({
    Action: "agent-registry:GetRegistry",
    Resource: { "Fn::GetAtt": [registryId, "RegistryArn"] },
  });
  expect(registryStatements[1]).toMatchObject({
    Action: [
      "agent-registry:GetRegistryRecord",
      "agent-registry:ListTagsForResource",
      "agent-registry:SubmitRegistryRecordForApproval",
    ],
    Resource: recordIds.map((id) => ({ "Fn::GetAtt": [id, "RecordArn"] })),
  });
  expect(JSON.stringify(registryStatements)).not.toContain("*");
});

test("GA SDK is bundled and both synchronous approval functions have bounded concurrency", () => {
  const handlers = Object.entries(
    template.findResources("AWS::Lambda::Function"),
  ).filter(([id]) => id.includes("GaRegistryApproval"));
  expect(handlers).toHaveLength(2);
  for (const [, resource] of handlers) {
    expect(resource.Properties.Runtime).toBe("nodejs22.x");
    expect(resource.Properties.ReservedConcurrentExecutions).toBe(10);
    expect(resource.Properties.Timeout).toBeLessThanOrEqual(150);
    expect(resource.Properties.Code.S3Key).toBeDefined();
  }
});
