/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: MIT-0
 */
import { Aws, Stack } from "aws-cdk-lib";
import { AccountPrincipal, Effect, ManagedPolicy, PolicyStatement, Role } from "aws-cdk-lib/aws-iam";
import { NagSuppressions } from "cdk-nag";
import { Construct } from "constructs";
import {
  PortalEnvironment,
  portalContainmentRoleName,
  portalContainmentTargetRoleName,
} from "./naming";

/**
 * Everything the containment authority may do in a cell, and nothing else:
 * read and change the resource policy of a Runtime (to add or remove the one
 * deny statement that blocks invocation), stop the Runtime's sessions, and
 * find those sessions. No API lists a Runtime's sessions, so their ids are
 * read from the names of the log streams the service creates per session in
 * each endpoint's log group (which is why the endpoints are listed). It
 * cannot invoke, update or delete a Runtime, cannot read a log event or run a
 * query, and cannot touch a Gateway, Memory, identity or any other resource.
 */
export const PORTAL_CONTAINMENT_TARGET_ACTIONS: readonly string[] = [
  "bedrock-agentcore:GetResourcePolicy",
  "bedrock-agentcore:PutResourcePolicy",
  "bedrock-agentcore:DeleteResourcePolicy",
  "bedrock-agentcore:StopRuntimeSession",
  "bedrock-agentcore:ListAgentRuntimeEndpoints",
];

/**
 * Optional second source of session ids, off by default: a Logs Insights
 * query over the spans log group and its result. IAM cannot restrict which
 * query is run, so a role that holds these can read span content, not only
 * session ids. See `spanSessionDiscovery`.
 */
export const PORTAL_CONTAINMENT_TARGET_LOGS_QUERY_ACTIONS: readonly string[] = ["logs:StartQuery"];
export const PORTAL_CONTAINMENT_TARGET_LOGS_RESULT_ACTIONS: readonly string[] = ["logs:GetQueryResults"];
/**
 * Session discovery from log stream names (`runtime-logs-<session id>`): the
 * names only, in the log groups of this account's Runtimes. No log event.
 */
export const PORTAL_CONTAINMENT_TARGET_LOG_STREAM_ACTIONS: readonly string[] = ["logs:DescribeLogStreams"];
/** The log groups AgentCore writes a Runtime endpoint's logs to. */
export const PORTAL_RUNTIME_LOG_GROUP_PREFIX = "/aws/bedrock-agentcore/runtimes/";

export interface PortalContainmentTargetRoleProps {
  readonly environment: PortalEnvironment;
  readonly platformAccountId: string;
  readonly externalId: string;
  /**
   * Also let the containment authority look for session ids in the cell's
   * spans (it finds a session of an instrumented agent that wrote no output).
   * Off by default: it grants a Logs Insights query on the spans log group,
   * and a role that can run a query there can read span content, which can
   * include prompts and tool output.
   */
  readonly spanSessionDiscovery?: boolean;
  /** Log groups holding the Runtimes' spans, for `spanSessionDiscovery`. Defaults to `aws/spans`. */
  readonly spansLogGroupNames?: readonly string[];
}

/**
 * Incident containment is the one deliberate exception to "central visibility
 * must not become central write access" (README section 9.3, "contain the
 * principal"). The cell grants it explicitly by deploying this role: it trusts
 * only the portal's containment function role, with the cell's external id,
 * and holds only the actions in {@link PORTAL_CONTAINMENT_TARGET_ACTIONS} on
 * this account's Runtimes, plus the two reads that find their sessions.
 * Releasing a contained agent needs a second person; that rule and the audit
 * trail live in the portal.
 */
export class PortalContainmentTargetRole extends Construct {
  readonly role: Role;

  constructor(scope: Construct, id: string, props: PortalContainmentTargetRoleProps) {
    super(scope, id);
    if (!/^\d{12}$/.test(props.platformAccountId)) {
      throw new Error("Portal containment target: platformAccountId must be 12 digits.");
    }
    if (!/^[\w+=,.@:/-]{16,128}$/.test(props.externalId)) {
      throw new Error("Portal containment target: externalId must be 16 to 128 characters of [A-Za-z0-9_+=,.@:/-].");
    }
    const stack = Stack.of(this);
    const caller = `arn:${Aws.PARTITION}:iam::${props.platformAccountId}:role/${portalContainmentRoleName(props.environment)}`;
    this.role = new Role(this, "Role", {
      roleName: portalContainmentTargetRoleName(props.environment),
      description:
        "Agent Factory Portal containment authority in this cell: block and unblock invocation of a Runtime and stop its sessions. Assumed only by the portal containment function.",
      assumedBy: new AccountPrincipal(props.platformAccountId).withConditions({
        ArnEquals: { "aws:PrincipalArn": caller },
        StringEquals: { "sts:ExternalId": props.externalId },
      }),
    });
    const policy = new ManagedPolicy(this, "Containment", {
      description: "Agent Factory Portal containment: Runtime resource policy and session stop only.",
      roles: [this.role],
      statements: [
        new PolicyStatement({
          sid: "ContainRuntimes",
          effect: Effect.ALLOW,
          actions: [...PORTAL_CONTAINMENT_TARGET_ACTIONS],
          resources: [`arn:${Aws.PARTITION}:bedrock-agentcore:${stack.region}:${stack.account}:runtime/*`],
        }),
        new PolicyStatement({
          sid: "FindRuntimeSessionStreams",
          effect: Effect.ALLOW,
          actions: [...PORTAL_CONTAINMENT_TARGET_LOG_STREAM_ACTIONS],
          resources: [
            `arn:${Aws.PARTITION}:logs:${stack.region}:${stack.account}:log-group:${PORTAL_RUNTIME_LOG_GROUP_PREFIX}*`,
          ],
        }),
      ],
    });
    if (props.spanSessionDiscovery) {
      policy.addStatements(
        new PolicyStatement({
          sid: "FindRuntimeSessionsInSpans",
          effect: Effect.ALLOW,
          actions: [...PORTAL_CONTAINMENT_TARGET_LOGS_QUERY_ACTIONS],
          resources: (props.spansLogGroupNames ?? ["aws/spans"]).map(
            (name) => `arn:${Aws.PARTITION}:logs:${stack.region}:${stack.account}:log-group:${name}:*`,
          ),
        }),
        new PolicyStatement({
          sid: "ReadSessionQueryResults",
          effect: Effect.ALLOW,
          actions: [...PORTAL_CONTAINMENT_TARGET_LOGS_RESULT_ACTIONS],
          resources: ["*"],
          conditions: { StringEquals: { "aws:RequestedRegion": stack.region } },
        }),
      );
    }
    NagSuppressions.addResourceSuppressions(
      policy,
      [
        {
          id: "AwsSolutions-IAM5",
          reason:
            "SEC-050: containment must reach any Runtime of this cell, including ones deployed after this role; the Runtime statement is scoped to this account and Region's Runtimes and to five actions; log stream names are listed only in the log groups of those Runtimes; with the optional spans source, Logs Insights results have no resource type and are pinned to the Region.",
        },
      ],
      true,
    );
  }
}
