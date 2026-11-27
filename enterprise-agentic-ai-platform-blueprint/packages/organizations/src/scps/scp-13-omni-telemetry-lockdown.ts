/**
 * SCP-13 — CloudWatch Omni telemetry lockdown (ADR-15, ADR-13 amended).
 *
 * The hub model works because the organization centralization rule pulls a
 * cell's telemetry from above: the cell cannot read, change or stop the rule.
 * What a cell principal CAN do is starve the rule at the source. This SCP
 * closes those switches for every principal in the Workstream OUs except the
 * Workload pipeline (and an optional named break-glass role):
 *
 *   1. Omni domains. One organization domain is created from the Management
 *      account; an account-level domain in a cell fragments sign-in and
 *      identity and is never wanted. Denied to everyone, no exemption.
 *   2. Omni spaces and their grants. Per-cell spaces exist only as the
 *      classification-driven fallback of ADR-15 and are deployed by the
 *      pipeline. Hand-made spaces, grants and access profiles are denied.
 *   3. Transaction Search. Spans reach `aws/spans` (and therefore the hub)
 *      only while the account's trace destination is CloudWatch Logs, the
 *      indexing rule is above zero and the X-Ray CloudWatch Logs resource
 *      policy exists. All three are pipeline-owned (TransactionSearchConstruct).
 *   4. AgentCore Runtime observability. Runtime logs and spans flow through
 *      CloudWatch Logs vended deliveries created by the Runtime stack;
 *      deleting or re-pointing a delivery silences the agent.
 *
 * IAM action prefix: CloudWatch Omni authorizes as `cloudwatch:*` (verified
 * against the AWS managed policies CloudWatchOmniSpaceAccessPolicy and
 * CloudWatchOmniDomainAccessPolicy, 2026-11-06).
 *
 * Exemptions require the reviewed protected authority manifest. Separate
 * ARN and RoleId checks bind each exception to an exact live IAM role entity.
 * There is no CDK role-name or account wildcard fallback.
 *
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: MIT-0
 */
import { toScpDefinition, type ScpDefinition } from "./index";
import {
  principalEntityDenyStatements,
  protectedRolesForPurpose,
  validateProtectedAuthorityManifest,
} from "../protected-authority";

export interface Scp13Options {
  /** Reviewed telemetry deployment and optional recovery identities. */
  readonly protectedAuthorityManifest?: unknown;
  /** Removed insecure option; rejected with migration guidance. */
  readonly pipelineRoleNamePatterns?: readonly string[];
  /** Removed insecure option; rejected with migration guidance. */
  readonly breakGlassRoleNames?: readonly string[];
}

/** Account-level Omni domain lifecycle: never in a cell. */
export const SCP13_DOMAIN_ACTIONS: readonly string[] = [
  "cloudwatch:CreateDomain",
  "cloudwatch:UpdateDomain",
  "cloudwatch:DeleteDomain",
  "cloudwatch:CreateDomainForOrganization",
  "cloudwatch:UpdateDomainForOrganization",
  "cloudwatch:DeleteDomainForOrganization",
];

/** Space, grant and access-profile lifecycle: pipeline only. */
export const SCP13_SPACE_ACTIONS: readonly string[] = [
  "cloudwatch:CreateSpace",
  "cloudwatch:UpdateSpace",
  "cloudwatch:DeleteSpace",
  "cloudwatch:CreateAccessGrant",
  "cloudwatch:DeleteAccessGrant",
  "cloudwatch:CreateAccessProfile",
  "cloudwatch:UpdateAccessProfile",
  "cloudwatch:DeleteAccessProfile",
];

/** The three switches that stop spans reaching aws/spans. */
export const SCP13_TRANSACTION_SEARCH_ACTIONS: readonly string[] = [
  "xray:UpdateTraceSegmentDestination",
  "xray:UpdateIndexingRule",
  "logs:PutResourcePolicy",
  "logs:DeleteResourcePolicy",
];

/** CloudWatch Logs vended deliveries that carry AgentCore Runtime telemetry. */
export const SCP13_DELIVERY_ACTIONS: readonly string[] = [
  "logs:DeleteDelivery",
  "logs:DeleteDeliverySource",
  "logs:DeleteDeliveryDestination",
  "logs:DeleteDeliveryDestinationPolicy",
  "logs:UpdateDeliveryConfiguration",
];

export function scp13OmniTelemetryLockdown(
  opts: Scp13Options = {},
): ScpDefinition {
  if (
    opts.pipelineRoleNamePatterns !== undefined ||
    opts.breakGlassRoleNames !== undefined
  ) {
    throw new Error(
      "SCP-13: role names and patterns are no longer accepted. Supply protectedAuthorityManifest with exact ARN/RoleId-bound telemetry identities and their authority protections.",
    );
  }
  const roles = protectedRolesForPurpose(
    validateProtectedAuthorityManifest(opts.protectedAuthorityManifest),
    "telemetry",
  );
  if (roles.length === 0) {
    throw new Error(
      "SCP-13: the protected authority manifest needs telemetry identities.",
    );
  }
  const everyone = {
    BoolIfExists: { "aws:PrincipalIsAWSService": "false" },
  };

  const body = {
    Version: "2012-10-17",
    Statement: [
      {
        Sid: "DenyAccountLevelOmniDomainInCells",
        Effect: "Deny",
        Action: Array.from(SCP13_DOMAIN_ACTIONS),
        Resource: "*",
        Condition: everyone,
      },
      ...principalEntityDenyStatements(
        "DenyOmniSpaceLifecycleExceptPipeline",
        SCP13_SPACE_ACTIONS,
        ["*"],
        roles,
        { awsServiceExempt: true },
      ),
      ...principalEntityDenyStatements(
        "DenyTransactionSearchTamperingExceptPipeline",
        SCP13_TRANSACTION_SEARCH_ACTIONS,
        ["*"],
        roles,
        { awsServiceExempt: true },
      ),
      ...principalEntityDenyStatements(
        "DenyRuntimeDeliveryTamperingExceptPipeline",
        SCP13_DELIVERY_ACTIONS,
        ["*"],
        roles,
        { awsServiceExempt: true },
      ),
    ],
  };

  return toScpDefinition(
    "scp-13",
    "AgenticAI-SCP-13-OmniTelemetryLockdown",
    "Cells cannot create Omni domains or tamper with telemetry; only protected exact ARN/RoleId-bound telemetry identities may manage pipeline controls (ADR-15).",
    body,
  );
}
