/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: MIT-0
 */
import * as path from "path";
import {
  Aws,
  CfnResource,
  CustomResource,
  Duration,
  RemovalPolicy,
  Stack,
} from "aws-cdk-lib";
import { PolicyStatement, Role, ServicePrincipal } from "aws-cdk-lib/aws-iam";
import { CfnFunction, Runtime } from "aws-cdk-lib/aws-lambda";
import { NodejsFunction } from "aws-cdk-lib/aws-lambda-nodejs";
import { LogGroup, RetentionDays } from "aws-cdk-lib/aws-logs";
import { Provider } from "aws-cdk-lib/custom-resources";
import { NagSuppressions } from "cdk-nag";
import { Construct } from "constructs";

export interface RegistryApprovalConstructProps {
  readonly registry: CfnResource;
  readonly registryId: string;
  readonly registryArn: string;
  readonly records: Readonly<
    Record<
      string,
      {
        readonly resource: CfnResource;
        readonly version: string;
        readonly descriptorData: string;
      }
    >
  >;
  readonly tags: Readonly<Record<string, string>>;
}

/** Submit only the producer's exact, version-bound native records. */
export class RegistryApprovalConstruct extends Construct {
  readonly resources: Readonly<Record<string, CustomResource>>;

  constructor(
    scope: Construct,
    id: string,
    props: RegistryApprovalConstructProps,
  ) {
    super(scope, id);
    const stack = Stack.of(this);
    const handlerLogs = new LogGroup(this, "HandlerLogs", {
      retention: RetentionDays.ONE_MONTH,
      removalPolicy: RemovalPolicy.DESTROY,
    });
    const frameworkLogs = new LogGroup(this, "FrameworkLogs", {
      retention: RetentionDays.ONE_MONTH,
      removalPolicy: RemovalPolicy.DESTROY,
    });
    const handlerRole = new Role(this, "HandlerRole", {
      assumedBy: new ServicePrincipal("lambda.amazonaws.com"),
    });
    const frameworkRole = new Role(this, "FrameworkRole", {
      assumedBy: new ServicePrincipal("lambda.amazonaws.com"),
    });
    for (const [role, logs] of [
      [handlerRole, handlerLogs],
      [frameworkRole, frameworkLogs],
    ] as const) {
      role.addToPolicy(
        new PolicyStatement({
          actions: ["logs:CreateLogStream", "logs:PutLogEvents"],
          resources: [logs.logGroupArn],
        }),
      );
      NagSuppressions.addResourceSuppressions(
        role,
        [
          {
            id: "AwsSolutions-IAM5",
            reason:
              "The generated log-group ARN permits its log streams only; this execution role has no account-wide logging or Registry wildcard permissions.",
          },
        ],
        true,
      );
    }
    handlerRole.addToPolicy(
      new PolicyStatement({
        actions: ["agent-registry:GetRegistry"],
        resources: [props.registryArn],
      }),
    );
    handlerRole.addToPolicy(
      new PolicyStatement({
        actions: [
          "agent-registry:GetRegistryRecord",
          "agent-registry:ListTagsForResource",
          "agent-registry:SubmitRegistryRecordForApproval",
        ],
        resources: Object.values(props.records).map(({ resource }) =>
          resource.getAtt("RecordArn").toString(),
        ),
      }),
    );
    const onEvent = new NodejsFunction(this, "Handler", {
      entry: path.join(__dirname, "../lambda/registry-approval/index.ts"),
      depsLockFilePath: path.join(__dirname, "../../../package-lock.json"),
      projectRoot: path.join(__dirname, "../../.."),
      handler: "handler",
      runtime: Runtime.NODEJS_22_X,
      timeout: Duration.seconds(120),
      memorySize: 256,
      reservedConcurrentExecutions: 10,
      role: handlerRole,
      logGroup: handlerLogs,
      bundling: {
        bundleAwsSDK: true,
        externalModules: [],
        minify: true,
      },
    });
    const provider = new Provider(this, "Provider", {
      onEventHandler: onEvent,
      frameworkOnEventRole: frameworkRole,
      logGroup: frameworkLogs,
    });
    // The framework synchronously invokes this handler; use the reviewed runtime
    // and cap both functions' concurrency rather than relying on framework defaults.
    for (const child of provider.node.findAll()) {
      if (child instanceof CfnFunction) {
        child.runtime = Runtime.NODEJS_22_X.name;
        child.reservedConcurrentExecutions = 10;
        child.timeout = 150;
      }
    }
    NagSuppressions.addResourceSuppressions(
      this,
      [
        {
          id: "AwsSolutions-L1",
          reason:
            "Node.js 22 is a supported Lambda runtime and is explicitly pinned for both the bundled GA Registry handler and the CDK provider framework.",
        },
      ],
      true,
    );
    const resources: Record<string, CustomResource> = {};
    for (const [name, record] of Object.entries(props.records)) {
      const resource = new CustomResource(this, `Record-${name}`, {
        resourceType: "Custom::AgenticAIGaRegistryApproval",
        serviceToken: provider.serviceToken,
        properties: {
          AccountId: stack.account,
          RegistryId: props.registryId,
          RegistryArn: props.registryArn,
          RecordId: record.resource.getAtt("RecordId").toString(),
          RecordArn: record.resource.getAtt("RecordArn").toString(),
          RecordName: name,
          RecordVersion: record.version,
          DescriptorData: record.descriptorData,
          Tags: {
            ...props.tags,
            "aws:cloudformation:stack-id": Aws.STACK_ID,
            "aws:cloudformation:stack-name": Aws.STACK_NAME,
            "aws:cloudformation:logical-id": record.resource.logicalId,
          },
        },
      });
      resource.node.addDependency(record.resource, props.registry);
      resources[name] = resource;
    }
    this.resources = resources;
  }
}
