/**
 * SCP-05 — Deny Guardrail Modification in Workload Accounts.
 *
 * Spec §2.2.6 L752-783. Delivery teams in workload accounts cannot
 * create/update/delete Bedrock Guardrails. Only the platform Guardrail Admin
 * role (deployed in platform-nonprod/prod per Phase 3) may do so. This
 * enforces segregation of duties per R-BED-011 and R-BED-012.
 *
 * For role sessions aws:PrincipalArn is the IAM role ARN. When the protected
 * authority manifest is supplied, a separate immutable RoleId gate prevents
 * same-name recreation from inheriting the exception.
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

export function scp05DenyGuardrailModification(
  platformGuardrailAdminRoleArn: string,
  protectedAuthorityManifest?: unknown,
): ScpDefinition {
  if (!platformGuardrailAdminRoleArn.startsWith("arn:aws:iam::")) {
    throw new Error(
      `SCP-05: platformGuardrailAdminRoleArn must be a full IAM role ARN; got '${platformGuardrailAdminRoleArn}'.`,
    );
  }

  // Derive the assumed-role session ARN pattern from the role ARN.
  // Role ARN: arn:aws:iam::<acct>:role/<path?>/<name>
  // Session ARN: arn:aws:sts::<acct>:assumed-role/<name>/*
  const match =
    /^arn:aws:iam::([0-9]{12}):role\/(?:[A-Za-z0-9+=,.@_-]+\/)*([A-Za-z0-9+=,.@_-]{1,64})$/.exec(
      platformGuardrailAdminRoleArn,
    );
  if (!match) {
    throw new Error(
      `SCP-05: platformGuardrailAdminRoleArn '${platformGuardrailAdminRoleArn}' is not a parseable role ARN.`,
    );
  }
  const accountId = match[1];
  const roleName = match[2];
  const assumedRoleArn = `arn:aws:sts::${accountId}:assumed-role/${roleName}/*`;
  const protectedRoles =
    protectedAuthorityManifest === undefined
      ? undefined
      : protectedRolesForPurpose(
          validateProtectedAuthorityManifest(protectedAuthorityManifest),
          "guardrail-admin",
        ).filter((role) => role.arn === platformGuardrailAdminRoleArn);
  if (protectedRoles !== undefined && protectedRoles.length !== 1) {
    throw new Error(
      "SCP-05: the configured Guardrail Admin must have one exact guardrail-admin identity in protectedAuthorityManifest.",
    );
  }
  const actions = [
    "bedrock:CreateGuardrail",
    "bedrock:UpdateGuardrail",
    "bedrock:DeleteGuardrail",
    "bedrock:CreateGuardrailVersion",
  ];

  const body = {
    Version: "2012-10-17",
    Statement:
      protectedRoles === undefined
        ? [
            {
              Sid: "DenyGuardrailModificationOutsidePlatformAdmin",
              Effect: "Deny",
              Action: actions,
              Resource: "*",
              Condition: {
                ArnNotLike: {
                  "aws:PrincipalArn": [
                    platformGuardrailAdminRoleArn,
                    assumedRoleArn,
                  ],
                },
                BoolIfExists: {
                  "aws:PrincipalIsAWSService": "false",
                },
              },
            },
          ]
        : principalEntityDenyStatements(
            "DenyGuardrailModificationOutsidePlatformAdmin",
            actions,
            ["*"],
            protectedRoles,
            { awsServiceExempt: true },
          ),
  };

  return toScpDefinition(
    "scp-05",
    "AgenticAI-SCP-05-DenyGuardrailModification",
    "Only the platform Guardrail Admin role may modify Bedrock Guardrails (spec §2.2.6).",
    body,
  );
}
