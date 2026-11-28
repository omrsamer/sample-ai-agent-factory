/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: MIT-0
 */
import { Aws, Stack } from "aws-cdk-lib";
import { AccountPrincipal, ArnPrincipal, Effect, IPrincipal, ManagedPolicy, PolicyStatement, Role } from "aws-cdk-lib/aws-iam";
import { NagSuppressions } from "cdk-nag";
import { Construct } from "constructs";
import { PortalEnvironment, portalExternalReaderRoleName } from "./naming";

/**
 * What an external inventory or governance tool may read: the list of
 * Runtimes with their versions and endpoints, the list and configuration of
 * Gateways, tags, and CloudWatch metrics. It cannot read a Runtime's own
 * configuration (`GetAgentRuntime` returns its environment variables, which
 * can hold more than an inventory needs), cannot invoke a model or an agent,
 * cannot read Memory, prompts, traces or logs, and cannot change or delete
 * anything.
 */
export const PORTAL_EXTERNAL_READER_AGENTCORE_ACTIONS: readonly string[] = [
  "bedrock-agentcore:ListAgentRuntimes",
  "bedrock-agentcore:ListAgentRuntimeVersions",
  "bedrock-agentcore:ListAgentRuntimeEndpoints",
  "bedrock-agentcore:ListGateways",
  "bedrock-agentcore:GetGateway",
  "bedrock-agentcore:ListGatewayTargets",
  "bedrock-agentcore:ListTagsForResource",
];
export const PORTAL_EXTERNAL_READER_METRIC_ACTIONS: readonly string[] = [
  "cloudwatch:GetMetricData",
  "cloudwatch:ListMetrics",
];

export interface PortalExternalReaderRoleProps {
  readonly environment: PortalEnvironment;
  /** Account of the external tool that assumes the role. */
  readonly trustedAccountId: string;
  /** Exact principal ARN in that account, when the tool publishes one. */
  readonly trustedPrincipalArn?: string;
  /** External id issued for this connection. */
  readonly externalId: string;
  /** Source IPv4 ranges the tool calls from, when it publishes them. */
  readonly sourceIpv4Cidrs?: readonly string[];
}

/**
 * A least-privilege, keyless connection for an external agent inventory or
 * governance product that wants to list this account's agents. The role is
 * assumed with an external id (no long-lived access key is created), can be
 * pinned to the tool's principal and source addresses, and holds read-only
 * inventory and metric actions only. Connector samples that ask for invoke
 * or delete permissions on `*` should be replaced by this role.
 */
export class PortalExternalReaderRole extends Construct {
  readonly role: Role;

  constructor(scope: Construct, id: string, props: PortalExternalReaderRoleProps) {
    super(scope, id);
    if (!/^\d{12}$/.test(props.trustedAccountId)) {
      throw new Error("External reader: trustedAccountId must be 12 digits.");
    }
    if (!/^[\w+=,.@:/-]{16,128}$/.test(props.externalId)) {
      throw new Error("External reader: externalId must be 16 to 128 characters of [A-Za-z0-9_+=,.@:/-].");
    }
    for (const cidr of props.sourceIpv4Cidrs ?? []) {
      if (!/^(\d{1,3}\.){3}\d{1,3}\/(\d|[12]\d|3[0-2])$/.test(cidr)) {
        throw new Error(`External reader: '${cidr}' is not an IPv4 CIDR.`);
      }
    }
    const stack = Stack.of(this);
    const conditions: Record<string, Record<string, unknown>> = {
      StringEquals: { "sts:ExternalId": props.externalId },
    };
    if (props.sourceIpv4Cidrs && props.sourceIpv4Cidrs.length > 0) {
      conditions.IpAddress = { "aws:SourceIp": [...props.sourceIpv4Cidrs] };
    }
    const principal: IPrincipal = props.trustedPrincipalArn
      ? new ArnPrincipal(props.trustedPrincipalArn).withConditions(conditions)
      : new AccountPrincipal(props.trustedAccountId).withConditions(conditions);
    if (props.trustedPrincipalArn && !props.trustedPrincipalArn.includes(`::${props.trustedAccountId}:`)) {
      throw new Error("External reader: trustedPrincipalArn must belong to trustedAccountId.");
    }
    this.role = new Role(this, "Role", {
      roleName: portalExternalReaderRoleName(props.environment),
      description:
        "Read-only agent inventory for an external governance tool. Assumed with an external id; no invoke, no data access, no change.",
      assumedBy: principal,
    });
    const policy = new ManagedPolicy(this, "Inventory", {
      description: "Read-only AgentCore inventory and CloudWatch metrics for an external governance tool.",
      roles: [this.role],
      statements: [
        new PolicyStatement({
          sid: "ReadAgentInventory",
          effect: Effect.ALLOW,
          actions: [...PORTAL_EXTERNAL_READER_AGENTCORE_ACTIONS],
          resources: [
            `arn:${Aws.PARTITION}:bedrock-agentcore:${stack.region}:${stack.account}:runtime/*`,
            `arn:${Aws.PARTITION}:bedrock-agentcore:${stack.region}:${stack.account}:gateway/*`,
          ],
        }),
        new PolicyStatement({
          sid: "ReadMetrics",
          effect: Effect.ALLOW,
          actions: [...PORTAL_EXTERNAL_READER_METRIC_ACTIONS],
          resources: ["*"],
          conditions: { StringEquals: { "aws:RequestedRegion": stack.region } },
        }),
      ],
    });
    NagSuppressions.addResourceSuppressions(
      policy,
      [
        {
          id: "AwsSolutions-IAM5",
          reason:
            "SEC-051: read-only inventory. AgentCore list operations and resources created after synthesis are scoped to this account and Region by resource type; CloudWatch metric reads have no resource type and are pinned to the Region.",
        },
      ],
      true,
    );
  }
}
