import { App, Aspects } from "aws-cdk-lib";
import { Match, Template } from "aws-cdk-lib/assertions";
import { AwsSolutionsChecks } from "cdk-nag";
import { RuntimeRouterStack, RuntimeRouterStackProps } from "../../pipelines/runtime-router-stack";

const props: RuntimeRouterStackProps = {
  env: { account: "111111111111", region: "eu-west-1" },
  runtimeId: "reviewed_runtime-abcdefghij", runtimeVersion: "2",
  sourceRevision: `s3-sha256:${"a".repeat(64)}`, functionName: "reviewed-runtime-router",
  routingRoleName: "ReviewedRuntimeRouting",
  healthAlarmName: "agenticai-runtime-canary-nonprod-shared-shared",
  pipelineCanaryRoleArn: "arn:aws:iam::111111111111:role/AgenticAI-WLP-shared-shared-Canary",
  baselineLambdaVersion: "1", baselineRuntimeVersion: "1",
};

test("router pins retained endpoints and publishes an immutable candidate while alias stays at baseline", () => {
  const app = new App();
  const stack = new RuntimeRouterStack(app, "Router", props);
  Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true }));
  const template = Template.fromStack(stack);
  template.hasResource("AWS::BedrockAgentCore::RuntimeEndpoint", {
    Properties: { AgentRuntimeId: props.runtimeId, AgentRuntimeVersion: "2", Name: "pinned_v2" },
    DeletionPolicy: "Retain", UpdateReplacePolicy: "Retain",
  });
  template.hasResourceProperties("AWS::Lambda::Alias", {
    Name: "live", FunctionVersion: "1",
  });
  template.hasResourceProperties("AWS::Lambda::Function", {
    Environment: { Variables: Match.objectLike({
      AGENTCORE_ENDPOINT: "pinned_v2", AGENTCORE_VERSION: "2", SOURCE_REVISION: props.sourceRevision,
    }) },
  });
  template.resourceCountIs("AWS::Lambda::Version", 1);
  template.resourceCountIs("AWS::CloudWatch::Alarm", 3);
  template.hasResourceProperties("AWS::CloudWatch::CompositeAlarm", {
    AlarmName: props.healthAlarmName,
  });
  template.hasResourceProperties("AWS::CloudWatch::Alarm", {
    AlarmName: `${props.healthAlarmName}-first-token`, Threshold: 1500,
    TreatMissingData: "breaching", ExtendedStatistic: "p99",
  });
  template.hasResourceProperties("AWS::IAM::Role", {
    RoleName: props.routingRoleName,
    AssumeRolePolicyDocument: Match.objectLike({ Statement: Match.arrayWith([
      Match.objectLike({ Principal: { AWS: props.pipelineCanaryRoleArn } }),
    ]) }),
  });
  const assembly = app.synth();
  expect(assembly.getStackArtifact(stack.artifactId).messages.filter(m => m.level === "error")).toEqual([]);
});

test.each([
  { runtimeVersion: "0" }, { sourceRevision: "unreviewed" },
  { baselineLambdaVersion: undefined, baselineRuntimeVersion: "1" },
  { baselineLambdaVersion: "1", baselineRuntimeVersion: undefined },
])("invalid or partial baseline identities fail before synthesis: %p", override => {
  expect(() => new RuntimeRouterStack(new App(), "Invalid", { ...props, ...override })).toThrow();
});
