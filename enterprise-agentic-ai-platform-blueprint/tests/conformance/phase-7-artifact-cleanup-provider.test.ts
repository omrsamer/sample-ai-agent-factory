import { App, Stack } from "aws-cdk-lib";
import { Template } from "aws-cdk-lib/assertions";
import { CfnRole } from "aws-cdk-lib/aws-iam";
import { CfnFunction } from "aws-cdk-lib/aws-lambda";
import { Construct } from "constructs";
import fs from "node:fs";
import { preserveArtifactCleanupPhysicalId } from "../../pipelines/artifact-cleanup-provider";
import { createPipelineArtifactBucket } from "../../pipelines/pipeline-artifacts";

function fixture(patched: boolean) {
  const app = new App();
  const stack = new Stack(app, "Workload", {
    env: { account: "111111111111", region: "eu-west-1" },
  });
  createPipelineArtifactBucket(stack, "Artifacts", {
    applicationId: "test", agentId: "test", tenantId: "test",
    costCentre: "test", environment: "pipeline",
  });
  const provider = stack.node.findChild("Custom::S3AutoDeleteObjectsCustomResourceProvider");
  if (patched) preserveArtifactCleanupPhysicalId(provider);
  return { app, stack, provider };
}

test("the source-owned bundle modifies only existing handler Code and its asset metadata", () => {
  const before = Template.fromStack(fixture(false).stack).toJSON();
  const after = Template.fromStack(fixture(true).stack).toJSON();
  expect(Object.keys(after.Resources)).toEqual(Object.keys(before.Resources));
  const handlerId = Object.keys(before.Resources).find(
    id => before.Resources[id].Type === "AWS::Lambda::Function",
  )!;
  const customId = Object.keys(before.Resources).find(
    id => before.Resources[id].Type === "Custom::S3AutoDeleteObjects",
  )!;
  expect(after.Resources[handlerId].Properties.Code)
    .not.toEqual(before.Resources[handlerId].Properties.Code);
  expect(after.Resources[customId]).toEqual(before.Resources[customId]);
  expect(after.Resources[customId].Properties.ServiceToken)
    .toEqual({ "Fn::GetAtt": [handlerId, "Arn"] });
  after.Resources[handlerId].Properties.Code = before.Resources[handlerId].Properties.Code;
  after.Resources[handlerId].Metadata = before.Resources[handlerId].Metadata;
  expect(after).toEqual(before);
});

test("the asset binds to the exact generated CfnFunction without changing its role or runtime", () => {
  const { provider, stack } = fixture(true);
  const handler = provider.node.findChild("Handler");
  expect(CfnFunction.isCfnFunction(handler)).toBe(true);
  expect(CfnRole.isCfnRole(provider.node.findChild("Role"))).toBe(true);
  const template = Template.fromStack(stack).toJSON();
  const roleId = Object.keys(template.Resources).find(
    id => id.startsWith("CustomS3AutoDeleteObjects") &&
      template.Resources[id].Type === "AWS::IAM::Role",
  )!;
  const functionId = Object.keys(template.Resources).find(
    id => template.Resources[id].Type === "AWS::Lambda::Function",
  )!;
  expect(template.Resources[functionId].Properties.Role)
    .toEqual({ "Fn::GetAtt": [roleId, "Arn"] });
  expect(template.Resources[functionId].Properties.Runtime).toBe("nodejs24.x");
  expect(template.Resources[functionId].Properties.Handler).toBe("index.handler");
});

test.each(["upstream", "patched"])("fails closed if the %s bundle differs", which => {
  const { provider } = fixture(false);
  const originalRead = fs.readFileSync;
  const spy = jest.spyOn(fs, "readFileSync").mockImplementation(((...args: any[]) => {
    const path = String(args[0]);
    const targeted = which === "upstream"
      ? path.includes("node_modules/aws-cdk-lib/custom-resource-handlers/")
      : path.includes("pipelines/assets/s3-auto-delete-objects-handler/index.js");
    return targeted ? Buffer.from("unreviewed provider bytes") : (originalRead as any)(...args);
  }) as typeof fs.readFileSync);
  try {
    expect(() => preserveArtifactCleanupPhysicalId(provider)).toThrow(/unexpected provider bundle/);
  } finally {
    spy.mockRestore();
  }
});

test("fails closed for a missing or wrongly typed generated Handler", () => {
  const app = new App();
  const stack = new Stack(app, "Other");
  const missing = new Construct(stack, "Missing");
  expect(() => preserveArtifactCleanupPhysicalId(missing)).toThrow(/exact generated provider Handler/);
  const wrong = new Construct(stack, "Wrong");
  new Construct(wrong, "Handler");
  expect(() => preserveArtifactCleanupPhysicalId(wrong)).toThrow(/exact generated provider Handler/);
});
