import { CfnOutput, Duration, RemovalPolicy, Stack, StackProps } from "aws-cdk-lib";
import { CfnRuntimeEndpoint } from "aws-cdk-lib/aws-bedrockagentcore";
import { Alarm, AlarmRule, AlarmState, ComparisonOperator, CompositeAlarm, Metric, TreatMissingData } from "aws-cdk-lib/aws-cloudwatch";
import { ArnPrincipal, PolicyDocument, PolicyStatement, Role, ServicePrincipal } from "aws-cdk-lib/aws-iam";
import { Alias, Code, Function, Runtime, Version } from "aws-cdk-lib/aws-lambda";
import { LogGroup, RetentionDays } from "aws-cdk-lib/aws-logs";
import { NagSuppressions } from "cdk-nag";
import { Construct } from "constructs";
import { readFileSync } from "fs";
import { join } from "path";

export interface RuntimeRouterStackProps extends StackProps {
  readonly runtimeId: string;
  readonly runtimeVersion: string;
  readonly sourceRevision: string;
  readonly functionName: string;
  readonly routingRoleName: string;
  readonly pipelineCanaryRoleArn: string;
  /** Health alarm consumed by the rollout, based on actual router invocations. */
  readonly healthAlarmName: string;
  readonly baselineLambdaVersion?: string;
  readonly baselineRuntimeVersion?: string;
}

/** Publish immutable endpoint-pinned router versions; bootstrap once before canary. */
export class RuntimeRouterStack extends Stack {
  constructor(scope: Construct, id: string, props: RuntimeRouterStackProps) {
    super(scope, id, props);
    if (!/^[A-Za-z][A-Za-z0-9_]{0,99}-[A-Za-z0-9]{10}$/.test(props.runtimeId) ||
        !/^[1-9]\d{0,39}$/.test(props.runtimeVersion) ||
        !/^(?:[0-9a-f]{40}|s3-sha256:[0-9a-f]{64})$/.test(props.sourceRevision) ||
        !/^[A-Za-z0-9_-]{1,64}$/.test(props.functionName) ||
        !/^[A-Za-z0-9+=,.@_-]{1,64}$/.test(props.routingRoleName) ||
        !/^agenticai-runtime-canary-[A-Za-z0-9_-]{1,200}$/.test(props.healthAlarmName) ||
        !/^arn:aws:iam::\d{12}:role\/[A-Za-z0-9+=,.@_/-]+$/.test(props.pipelineCanaryRoleArn) ||
        (props.baselineLambdaVersion !== undefined && (!/^[1-9]\d*$/.test(props.baselineLambdaVersion) ||
          !props.baselineRuntimeVersion || !/^[1-9]\d{0,39}$/.test(props.baselineRuntimeVersion))) ||
        (props.baselineRuntimeVersion !== undefined && props.baselineLambdaVersion === undefined)) {
      throw new Error("RuntimeRouterStack requires exact runtime/source identities and published baseline.");
    }
    const runtimeArn = `arn:${this.partition}:bedrock-agentcore:${this.region}:${this.account}:runtime/${props.runtimeId}`;
    const endpointName = `pinned_v${props.runtimeVersion}`;
    const endpoint = new CfnRuntimeEndpoint(this, `EndpointV${props.runtimeVersion}`, {
      agentRuntimeId: props.runtimeId, agentRuntimeVersion: props.runtimeVersion,
      name: endpointName,
    });
    // Baseline router versions retain their exact endpoints through updates.
    endpoint.applyRemovalPolicy(RemovalPolicy.RETAIN);
    const executionRole = new Role(this, "ExecutionRole", {
      assumedBy: new ServicePrincipal("lambda.amazonaws.com"),
      inlinePolicies: { InvokePinnedEndpoint: new PolicyDocument({ statements: [
        new PolicyStatement({ actions: ["bedrock-agentcore:InvokeAgentRuntime"],
          resources: [runtimeArn, ...new Set([props.runtimeVersion, props.baselineRuntimeVersion]
            .filter((version): version is string => Boolean(version))
            .map(version => `${runtimeArn}/runtime-endpoint/pinned_v${version}`))] }),
      ] }) },
    });
    const router = new Function(this, "Router", {
      functionName: props.functionName, runtime: Runtime.PYTHON_3_13, handler: "index.handler",
      code: Code.fromInline(readFileSync(join(__dirname, "runtime_router.py"), "utf8")),
      timeout: Duration.seconds(75), role: executionRole,
      logGroup: new LogGroup(this, "RouterLogs", {
        logGroupName: `/aws/lambda/${props.functionName}`, retention: RetentionDays.ONE_WEEK,
        removalPolicy: RemovalPolicy.DESTROY,
      }),
      environment: { AGENTCORE_RUNTIME_ARN: runtimeArn, AGENTCORE_ENDPOINT: endpointName,
        AGENTCORE_VERSION: props.runtimeVersion, SOURCE_REVISION: props.sourceRevision,
        ROUTER_FUNCTION_NAME: props.functionName },
    });
    router.node.addDependency(endpoint);
    const candidate = router.currentVersion;
    candidate.applyRemovalPolicy(RemovalPolicy.RETAIN);
    const baseline = props.baselineLambdaVersion
      ? Version.fromVersionAttributes(this, "PublishedBaseline", {
          lambda: router, version: props.baselineLambdaVersion,
        })
      : candidate;
    const alias = new Alias(this, "LiveAlias", { aliasName: "live", version: baseline });
    const errors = new Alarm(this, "InvocationFailures", {
      alarmName: `${props.healthAlarmName}-errors`,
      metric: router.metricErrors({ period: Duration.minutes(1), statistic: "Sum" }),
      threshold: 0, comparisonOperator: ComparisonOperator.GREATER_THAN_THRESHOLD,
      evaluationPeriods: 1, treatMissingData: TreatMissingData.NOT_BREACHING,
    });
    const completions = new Alarm(this, "CompletionFailures", {
      alarmName: `${props.healthAlarmName}-completion`,
      metric: new Metric({ namespace: "agenticai/runtime-canary", metricName: "CompletionFailures",
        dimensionsMap: { FunctionName: props.functionName }, statistic: "Sum", period: Duration.minutes(1) }),
      threshold: 0, comparisonOperator: ComparisonOperator.GREATER_THAN_THRESHOLD,
      evaluationPeriods: 1, treatMissingData: TreatMissingData.BREACHING,
    });
    const latency = new Alarm(this, "InferenceFirstToken", {
      alarmName: `${props.healthAlarmName}-first-token`,
      metric: new Metric({ namespace: "agenticai/runtime-canary", metricName: "InferenceFirstTokenMs",
        dimensionsMap: { FunctionName: props.functionName }, statistic: "p99", period: Duration.minutes(1) }),
      threshold: 1500, comparisonOperator: ComparisonOperator.GREATER_THAN_THRESHOLD,
      evaluationPeriods: 1, treatMissingData: TreatMissingData.BREACHING,
    });
    const health = new CompositeAlarm(this, "CanaryHealth", {
      compositeAlarmName: props.healthAlarmName,
      alarmDescription: "Real invocation errors, incomplete agent responses, or first-token p99 above 1500ms. Missing sampled traffic blocks promotion.",
      alarmRule: AlarmRule.anyOf(...[errors, completions, latency].map(
        alarm => AlarmRule.fromAlarm(alarm, AlarmState.ALARM))),
    });
    const control = new Role(this, "RoutingRole", {
      roleName: props.routingRoleName, assumedBy: new ArnPrincipal(props.pipelineCanaryRoleArn),
      inlinePolicies: { ManageOwnedCanary: new PolicyDocument({ statements: [
        new PolicyStatement({ actions: ["lambda:GetAlias", "lambda:UpdateAlias"],
          resources: [alias.functionArn] }),
        new PolicyStatement({ actions: ["lambda:GetFunctionConfiguration"],
          resources: [`${router.functionArn}:*`] }),
        new PolicyStatement({ actions: ["bedrock-agentcore:GetAgentRuntimeEndpoint"],
          resources: [runtimeArn, `${runtimeArn}/runtime-endpoint/*`] }),
        new PolicyStatement({ actions: ["cloudwatch:DescribeAlarms"], resources: ["*"] }),
      ] }) },
    });
    NagSuppressions.addResourceSuppressions(control, [{ id: "AwsSolutions-IAM5",
      reason: "Published versions and endpoint versions belong to this exact owned router/runtime; DescribeAlarms has no resource-level authorization." }], true);
    NagSuppressions.addResourceSuppressions(router, [{ id: "AwsSolutions-L1",
      reason: "The router uses the supported Python3.13 runtime." }], true);
    new CfnOutput(this, "AliasArn", { value: alias.functionArn });
    new CfnOutput(this, "CandidateLambdaVersion", { value: candidate.version });
    new CfnOutput(this, "RoutingRoleArn", { value: control.roleArn });
    new CfnOutput(this, "EndpointName", { value: endpointName });
    new CfnOutput(this, "HealthAlarmName", { value: health.alarmName });
  }
}
