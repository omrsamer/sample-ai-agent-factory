import { App, PermissionsBoundary, Stack } from "aws-cdk-lib";
import { Template } from "aws-cdk-lib/assertions";
import { Role, ServicePrincipal } from "aws-cdk-lib/aws-iam";
import { WorkloadPipelineStack } from "../../pipelines/workload-pipeline-stack";
import { createPipelineArtifactBucket } from "../../pipelines/pipeline-artifacts";

const DEFAULT = "CodexTest-us-west-2-RoleBoundary";
const PIPELINE = "CodexTest-us-west-2-PipelineBoundary";
const CLEANUP = "CodexTest-us-west-2-ArtifactCleanupBoundary";
const KEY = "agenticai/artifactCleanupRoleBoundaryName";

function context(extra: Record<string, unknown> = {}) {
  return {
    "@aws-cdk/core:bootstrapQualifier": "secfix26",
    "@aws-cdk/core:permissionsBoundary": { name: DEFAULT },
    "agenticai/bootstrapQualifier": "secfix26",
    "agenticai/workloadRoleBoundaryName": DEFAULT,
    "agenticai/pipelineRoleBoundaryName": PIPELINE,
    ...extra,
  };
}

function workload(extra: Record<string, unknown> = {}) {
  const app = new App({ context: context(extra) });
  const stack = new WorkloadPipelineStack(app, "Workload", {
    env: { account: "111111111111", region: "us-west-2" },
    permissionsBoundary: PermissionsBoundary.fromName(PIPELINE),
    workloadPermissionsBoundaryName: DEFAULT,
    githubRepo: "aws-samples/sample-ai-agent-factory",
    githubConnectionArn: "arn:aws:codestar-connections:us-west-2:111111111111:connection/abc-123",
    tenantId: "demo",
    agentId: "primary",
    costCentre: "engineering",
    workloadNonprodEnv: { account: "444444444444", region: "us-west-2" },
    workloadProdEnv: { account: "555555555555", region: "us-west-2" },
    workloadNonprodAvailabilityZones: ["us-west-2a", "us-west-2b", "us-west-2c"],
    workloadProdAvailabilityZones: ["us-west-2a", "us-west-2b", "us-west-2c"],
  });
  new Role(stack, "UnrelatedRole", { assumedBy: new ServicePrincipal("lambda.amazonaws.com") });
  return { app, stack, template: Template.fromStack(stack).toJSON() };
}

function roleIds(template: any) {
  return Object.keys(template.Resources).filter(id => template.Resources[id].Type === "AWS::IAM::Role");
}

test("omitted feature retains the inherited provider boundary", () => {
  const { template } = workload();
  const id = roleIds(template).find(id => id.startsWith("CustomS3AutoDeleteObjects"));
  expect(id).toBeDefined();
  expect(JSON.stringify(template.Resources[id!].Properties.PermissionsBoundary)).toContain(PIPELINE);
});

test("public exact-role override changes one boundary and preserves the entire remaining template", () => {
  const before = workload().template;
  const after = workload({ [KEY]: CLEANUP }).template;
  expect(roleIds(after)).toEqual(roleIds(before));
  const id = roleIds(before).find(id => id.startsWith("CustomS3AutoDeleteObjects"))!;
  expect(JSON.stringify(after.Resources[id].Properties.PermissionsBoundary)).toContain(CLEANUP);
  expect(after.Resources[id].Properties.AssumeRolePolicyDocument)
    .toEqual(before.Resources[id].Properties.AssumeRolePolicyDocument);
  after.Resources[id].Properties.PermissionsBoundary = before.Resources[id].Properties.PermissionsBoundary;
  expect(after).toEqual(before);
});

test("other artifact-provider stacks retain their default boundary with the feature present", () => {
  const app = new App({ context: context({ [KEY]: CLEANUP }) });
  const other = new Stack(app, "Unrelated", {
    env: { account: "111111111111", region: "us-west-2" },
  });
  createPipelineArtifactBucket(other, "Artifacts", {
    applicationId: "other", agentId: "other", tenantId: "other",
    costCentre: "engineering", environment: "nonprod",
  });
  const template = Template.fromStack(other).toJSON();
  for (const id of roleIds(template)) {
    expect(JSON.stringify(template.Resources[id].Properties.PermissionsBoundary)).toContain(DEFAULT);
    expect(JSON.stringify(template.Resources[id].Properties.PermissionsBoundary)).not.toContain(CLEANUP);
  }
});

test.each([
  ["foreign name", { [KEY]: "Foreign-ArtifactCleanupBoundary" }],
  ["ARN instead of name", { [KEY]: "arn:aws:iam::111111111111:policy/" + CLEANUP }],
  ["default bootstrap", { [KEY]: CLEANUP, "agenticai/bootstrapQualifier": "hnb659fds" }],
  ["missing bootstrap", { [KEY]: CLEANUP, "agenticai/bootstrapQualifier": undefined }],
  ["invalid bootstrap", { [KEY]: CLEANUP, "agenticai/bootstrapQualifier": "secfix26!" }],
  ["missing default", { [KEY]: CLEANUP, "agenticai/workloadRoleBoundaryName": undefined }],
  ["foreign pipeline", { [KEY]: CLEANUP, "agenticai/pipelineRoleBoundaryName": "Foreign-PipelineBoundary" }],
])("fails closed for %s context", (_name, invalid) => {
  expect(() => workload(invalid)).toThrow(/artifact cleanup boundary must match/);
});
