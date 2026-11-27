/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: MIT-0
 */
import { Aws, RemovalPolicy, Stack } from "aws-cdk-lib";
import { Effect, PolicyStatement, ServicePrincipal } from "aws-cdk-lib/aws-iam";
import { IKey } from "aws-cdk-lib/aws-kms";
import { LogGroup, RetentionDays } from "aws-cdk-lib/aws-logs";
import { CfnIPSet, CfnLoggingConfiguration, CfnWebACL } from "aws-cdk-lib/aws-wafv2";
import { NagSuppressions } from "cdk-nag";
import { Construct } from "constructs";
import { PortalEnvironment } from "./naming";

export interface PortalEdgeWebAclProps {
  readonly environment: PortalEnvironment;
  /**
   * IPv4 CIDR ranges allowed to reach the portal. When set, every other source
   * is blocked. When empty the portal is reachable from any address and relies
   * on sign-in, the managed rule groups and the rate limit.
   */
  readonly allowedIpv4Cidrs: readonly string[];
  /** IPv6 CIDR ranges allowed to reach the portal. */
  readonly allowedIpv6Cidrs?: readonly string[];
  /** Requests per five minutes from one address before it is blocked. */
  readonly rateLimit?: number;
  /** Operator-provisioned key (us-east-1) for the web ACL log group. */
  readonly logsKey?: IKey;
}

const CIDR_V4 = /^(\d{1,3}\.){3}\d{1,3}\/(\d|[12]\d|3[0-2])$/;
const CIDR_V6 = /^[0-9a-fA-F:]+\/(\d|[1-9]\d|1[01]\d|12[0-8])$/;

/**
 * Web ACL for the portal's Amazon CloudFront distribution. CloudFront-scope
 * web ACLs exist only in us-east-1, so this construct lives in its own stack.
 */
export class PortalEdgeWebAcl extends Construct {
  readonly webAcl: CfnWebACL;

  constructor(scope: Construct, id: string, props: PortalEdgeWebAclProps) {
    super(scope, id);
    const v4 = [...props.allowedIpv4Cidrs];
    const v6 = [...(props.allowedIpv6Cidrs ?? [])];
    for (const cidr of v4) {
      if (!CIDR_V4.test(cidr)) throw new Error(`Portal web ACL: '${cidr}' is not an IPv4 CIDR.`);
    }
    for (const cidr of v6) {
      if (!CIDR_V6.test(cidr)) throw new Error(`Portal web ACL: '${cidr}' is not an IPv6 CIDR.`);
    }
    const restricted = v4.length + v6.length > 0;
    const metric = (name: string) => ({
      cloudWatchMetricsEnabled: true,
      sampledRequestsEnabled: true,
      metricName: `agenticai-portal-${props.environment}-${name}`,
    });

    const rules: CfnWebACL.RuleProperty[] = [];
    let priority = 0;
    if (restricted) {
      const statements: CfnWebACL.StatementProperty[] = [];
      if (v4.length > 0) {
        const set = new CfnIPSet(this, "AllowedIpv4", {
          name: `agenticai-portal-${props.environment}-ipv4`,
          scope: "CLOUDFRONT",
          ipAddressVersion: "IPV4",
          addresses: v4,
          description: "Sources allowed to reach the Agent Factory Portal, IPv4",
        });
        statements.push({ ipSetReferenceStatement: { arn: set.attrArn } });
      }
      if (v6.length > 0) {
        const set = new CfnIPSet(this, "AllowedIpv6", {
          name: `agenticai-portal-${props.environment}-ipv6`,
          scope: "CLOUDFRONT",
          ipAddressVersion: "IPV6",
          addresses: v6,
          description: "Sources allowed to reach the Agent Factory Portal, IPv6",
        });
        statements.push({ ipSetReferenceStatement: { arn: set.attrArn } });
      }
      const allowed: CfnWebACL.StatementProperty =
        statements.length === 1 ? statements[0] : { orStatement: { statements } };
      rules.push({
        name: "BlockSourcesOutsideAllowList",
        priority: priority++,
        action: { block: {} },
        statement: { notStatement: { statement: allowed } },
        visibilityConfig: metric("outside-allow-list"),
      });
    }
    rules.push({
      name: "RateLimitPerSource",
      priority: priority++,
      action: { block: {} },
      statement: {
        rateBasedStatement: { limit: props.rateLimit ?? 1000, aggregateKeyType: "IP" },
      },
      visibilityConfig: metric("rate-limit"),
    });
    for (const group of [
      "AWSManagedRulesAmazonIpReputationList",
      "AWSManagedRulesCommonRuleSet",
      "AWSManagedRulesKnownBadInputsRuleSet",
    ]) {
      rules.push({
        name: group,
        priority: priority++,
        overrideAction: { none: {} },
        statement: { managedRuleGroupStatement: { vendorName: "AWS", name: group } },
        visibilityConfig: metric(group.replace("AWSManagedRules", "").toLowerCase()),
      });
    }

    this.webAcl = new CfnWebACL(this, "WebAcl", {
      // Named so that the residue inventory can recognise it.
      name: `agenticai-portal-${props.environment}`,
      scope: "CLOUDFRONT",
      description: `Agent Factory Portal ${props.environment} edge protection`,
      defaultAction: { allow: {} },
      rules,
      visibilityConfig: metric("web-acl"),
    });

    // Web ACL logs. AWS WAF requires the log group name to start with
    // `aws-waf-logs-`.
    const stack = Stack.of(this);
    const logGroup = new LogGroup(this, "Logs", {
      logGroupName: `aws-waf-logs-agenticai-portal-${props.environment}`,
      retention: RetentionDays.ONE_YEAR,
      removalPolicy: RemovalPolicy.DESTROY,
      encryptionKey: props.logsKey,
    });
    logGroup.addToResourcePolicy(
      new PolicyStatement({
        sid: "AllowWafLogDelivery",
        effect: Effect.ALLOW,
        principals: [new ServicePrincipal("delivery.logs.amazonaws.com")],
        actions: ["logs:CreateLogStream", "logs:PutLogEvents"],
        resources: [`${logGroup.logGroupArn}:*`],
        conditions: {
          StringEquals: { "aws:SourceAccount": stack.account },
          ArnLike: { "aws:SourceArn": `arn:${Aws.PARTITION}:logs:${stack.region}:${stack.account}:*` },
        },
      }),
    );
    const logging = new CfnLoggingConfiguration(this, "Logging", {
      resourceArn: this.webAcl.attrArn,
      logDestinationConfigs: [
        `arn:${Aws.PARTITION}:logs:${stack.region}:${stack.account}:log-group:${logGroup.logGroupName}`,
      ],
      redactedFields: [{ singleHeader: { Name: "authorization" } }, { singleHeader: { Name: "cookie" } }],
    });
    logging.node.addDependency(logGroup);
    if (!props.logsKey) {
      NagSuppressions.addResourceSuppressions(
        logGroup,
        [
          {
            id: "NIST.800.53.R5-CloudWatchLogGroupEncrypted",
            reason:
              "SEC-046: CloudWatch Logs encrypts log data at rest by default. A customer managed key is supplied by operators through agenticai/portalEdgeLogsKeyArn; the edge stack does not create or tag keys.",
          },
        ],
        true,
      );
    }
  }
}
