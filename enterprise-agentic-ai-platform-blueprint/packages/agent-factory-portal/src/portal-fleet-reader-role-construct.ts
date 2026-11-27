/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: MIT-0
 */
import { Aws, Stack } from "aws-cdk-lib";
import {
  AccountPrincipal,
  Effect,
  ManagedPolicy,
  PolicyStatement,
  Role,
} from "aws-cdk-lib/aws-iam";
import { NagSuppressions } from "cdk-nag";
import { Construct } from "constructs";
import {
  PortalEnvironment,
  portalApiRoleArn,
  portalFleetReaderRoleName,
} from "./naming";

/**
 * Read-only actions the portal may use inside a Workstream cell account.
 *
 * "Central visibility must not become central write access": every entry is a
 * Get, List, Describe, StartQuery, StopQuery or GetQueryResults operation. The
 * conformance suite asserts the rendered policy holds nothing else.
 */
export const PORTAL_FLEET_READER_AGENTCORE_ACTIONS: readonly string[] = [
  "bedrock-agentcore:GetAgentRuntime",
  "bedrock-agentcore:ListAgentRuntimes",
  "bedrock-agentcore:ListAgentRuntimeVersions",
  "bedrock-agentcore:ListAgentRuntimeEndpoints",
  "bedrock-agentcore:GetGateway",
  "bedrock-agentcore:ListGateways",
  "bedrock-agentcore:GetGatewayTarget",
  "bedrock-agentcore:ListGatewayTargets",
  "bedrock-agentcore:GetPolicyEngine",
  "bedrock-agentcore:ListPolicyEngines",
  "bedrock-agentcore:GetPolicy",
  "bedrock-agentcore:ListPolicies",
  "bedrock-agentcore:GetMemory",
  "bedrock-agentcore:ListMemories",
];

/** CloudWatch reads that IAM authorizes against `*` only. */
export const PORTAL_FLEET_READER_CLOUDWATCH_ACTIONS: readonly string[] = [
  "cloudwatch:DescribeAlarms",
  "cloudwatch:DescribeAlarmHistory",
  "cloudwatch:GetMetricData",
  "cloudwatch:ListMetrics",
];

/** Logs Insights over the spans log group. */
export const PORTAL_FLEET_READER_LOGS_QUERY_ACTIONS: readonly string[] = [
  "logs:StartQuery",
];

/** Query-result reads, which IAM authorizes against `*` only. */
export const PORTAL_FLEET_READER_LOGS_RESULT_ACTIONS: readonly string[] = [
  "logs:GetQueryResults",
  "logs:StopQuery",
  "logs:DescribeLogGroups",
];

const READ_ONLY_OPERATION = /^(Get|List|Describe|StartQuery|StopQuery)/;

export function assertPortalReadOnlyAction(action: string): void {
  const operation = action.slice(action.indexOf(":") + 1);
  if (!READ_ONLY_OPERATION.test(operation)) {
    throw new Error(
      `Portal fleet reader: '${action}' is not a read-only operation.`,
    );
  }
}

export interface PortalFleetReaderRoleProps {
  readonly environment: PortalEnvironment;
  /** Platform account that hosts the portal API. */
  readonly platformAccountId: string;
  /** Shared secret the portal API must present when assuming the role. */
  readonly externalId: string;
  /** Log groups the portal may query for agent spans. Defaults to `aws/spans`. */
  readonly spansLogGroupNames?: readonly string[];
}

/**
 * The single role the portal API assumes in a Workstream cell account. It can
 * be assumed only by the exact portal API execution role of the Platform
 * account, and only with the external id.
 */
export class PortalFleetReaderRole extends Construct {
  readonly role: Role;

  constructor(scope: Construct, id: string, props: PortalFleetReaderRoleProps) {
    super(scope, id);
    if (!/^\d{12}$/.test(props.platformAccountId)) {
      throw new Error("Portal fleet reader: platformAccountId must be 12 digits.");
    }
    if (!/^[\w+=,.@:/-]{16,128}$/.test(props.externalId)) {
      throw new Error(
        "Portal fleet reader: externalId must be 16 to 128 characters of [A-Za-z0-9_+=,.@:/-].",
      );
    }
    const all = [
      ...PORTAL_FLEET_READER_AGENTCORE_ACTIONS,
      ...PORTAL_FLEET_READER_CLOUDWATCH_ACTIONS,
      ...PORTAL_FLEET_READER_LOGS_QUERY_ACTIONS,
      ...PORTAL_FLEET_READER_LOGS_RESULT_ACTIONS,
    ];
    all.forEach(assertPortalReadOnlyAction);

    const stack = Stack.of(this);
    const callerArn = portalApiRoleArn(
      Aws.PARTITION,
      props.platformAccountId,
      props.environment,
    );
    // The account principal plus an exact aws:PrincipalArn condition keeps the
    // trust policy valid whether or not the portal role exists yet, so the
    // cell and the Platform account can be deployed in either order.
    this.role = new Role(this, "Role", {
      roleName: portalFleetReaderRoleName(props.environment),
      description:
        "Agent Factory Portal fleet reader. Read-only; assumed only by the portal API role of the Platform account.",
      assumedBy: new AccountPrincipal(props.platformAccountId).withConditions({
        ArnEquals: { "aws:PrincipalArn": callerArn },
        StringEquals: { "sts:ExternalId": props.externalId },
      }),
    });

    const policy = new ManagedPolicy(this, "ReadOnly", {
      description: "Agent Factory Portal fleet reader: read-only AgentCore, CloudWatch and spans access.",
      roles: [this.role],
    });
    const agentcoreArn = (resource: string) =>
      `arn:${Aws.PARTITION}:bedrock-agentcore:${stack.region}:${stack.account}:${resource}`;
    policy.addStatements(
      new PolicyStatement({
        sid: "PortalReadAgentCore",
        effect: Effect.ALLOW,
        actions: [...PORTAL_FLEET_READER_AGENTCORE_ACTIONS],
        resources: [
          agentcoreArn("runtime/*"),
          agentcoreArn("gateway/*"),
          agentcoreArn("policy-engine/*"),
          agentcoreArn("memory/*"),
        ],
      }),
    );
    policy.addStatements(
      new PolicyStatement({
        sid: "PortalReadCloudWatch",
        effect: Effect.ALLOW,
        actions: [...PORTAL_FLEET_READER_CLOUDWATCH_ACTIONS],
        resources: ["*"],
        conditions: { StringEquals: { "aws:RequestedRegion": stack.region } },
      }),
    );
    const logGroups = props.spansLogGroupNames ?? ["aws/spans"];
    policy.addStatements(
      new PolicyStatement({
        sid: "PortalQuerySpans",
        effect: Effect.ALLOW,
        actions: [...PORTAL_FLEET_READER_LOGS_QUERY_ACTIONS],
        resources: logGroups.map(
          (name) =>
            `arn:${Aws.PARTITION}:logs:${stack.region}:${stack.account}:log-group:${name}:*`,
        ),
      }),
    );
    policy.addStatements(
      new PolicyStatement({
        sid: "PortalReadQueryResults",
        effect: Effect.ALLOW,
        actions: [...PORTAL_FLEET_READER_LOGS_RESULT_ACTIONS],
        resources: ["*"],
        conditions: { StringEquals: { "aws:RequestedRegion": stack.region } },
      }),
    );

    NagSuppressions.addResourceSuppressions(
      policy,
      [
        {
          id: "AwsSolutions-IAM5",
          reason:
            "SEC-038: read-only fleet visibility. AgentCore list operations and resources created by Workstream pipelines cannot be enumerated at synthesis, so the statement is scoped to this account and Region by resource type; CloudWatch alarm, metric and Logs Insights result reads have no resource type in the Service Authorization Reference and are pinned to the Region by aws:RequestedRegion. The policy holds no mutating action.",
        },
      ],
      true,
    );
  }
}
