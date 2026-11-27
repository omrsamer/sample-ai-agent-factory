/**
 * SCP-09 — AgentCore Gateway Mutation Lockdown.
 *
 * Under D-03 v3, AgentCore Gateway is deployed into the workstream account by
 * the platform pipeline but is PLATFORM-GOVERNED. Any mutation of the Gateway
 * (changing targets, Cedar, the Lambda interceptor, or tags) must only be
 * possible only from approved, entity-bound GatewayAdmin roles in configured
 * Workstream accounts. Those roles are created by the
 * Workload pipeline before Gateway deployment and trust only Lambda, so the
 * AgentCore API call executes in the account that owns the Gateway.
 * Every other principal — including the workload account's root / admin IAM
 * user / any runtime role — must be denied.
 *
 * `CreateGateway` is also denied so a workstream admin cannot sidestep the
 * lockdown by creating a rogue unmanaged Gateway alongside the platform one.
 *
 * IAM evaluates aws:PrincipalArn as the IAM role ARN for an assumed-role
 * session. A separate aws:userid deny binds the exception to the approved
 * live RoleId, so deleting and recreating a role cannot inherit it.
 * OrganizationConstruct installs the authority protections before this SCP.
 *
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: MIT-0
 */
import {
  SCP_BODY_SOFT_LIMIT,
  toScpDefinition,
  type ScpDefinition,
} from "./index";
import {
  principalEntityDenyStatements,
  protectedRolesForPurpose,
  validateProtectedAuthorityManifest,
} from "../protected-authority";

export interface Scp09Options {
  /** Workstream accounts hosting pipeline-created environment GatewayAdmin roles. */
  readonly workloadAccountIds: readonly string[];
  /** Reviewed exact identities, controllers and protected execution consumers. */
  readonly protectedAuthorityManifest?: unknown;
}

export function scp09GatewayMutationLockdown(
  opts: Scp09Options,
): ScpDefinition {
  const workloadAccountIds = [...new Set(opts.workloadAccountIds)].sort();
  if (
    workloadAccountIds.length === 0 ||
    workloadAccountIds.some((accountId) => !/^[0-9]{12}$/.test(accountId))
  ) {
    throw new Error(
      "SCP-09: workloadAccountIds must be a non-empty list of 12-digit account IDs.",
    );
  }

  const manifest = validateProtectedAuthorityManifest(
    opts.protectedAuthorityManifest,
  );
  const admins = protectedRolesForPurpose(manifest, "gateway-admin");
  // Native Cedar resources are provisioned by CloudFormation, rather than the
  // GatewayAdmin Lambda. Admit only the exact controllers from the reviewed
  // native-resource graph; per-resource authority guards narrow their scope.
  const nativeControllerIds = new Set(
    manifest.resources
      .filter((resource) =>
        ["agentcore-policy-engine", "agentcore-policy"].includes(resource.kind),
      )
      .flatMap((resource) => resource.controllerIds),
  );
  const policyControllers = manifest.roles.filter(
    (role) =>
      admins.some((admin) => admin.id === role.id) ||
      nativeControllerIds.has(role.id),
  );
  const approvedAccounts = [
    ...new Set(admins.map((role) => role.arn.split(":")[4])),
  ].sort();
  if (
    JSON.stringify(approvedAccounts) !== JSON.stringify(workloadAccountIds) ||
    workloadAccountIds.some(
      (account) => !manifest.governedAccountIds.includes(account),
    )
  ) {
    throw new Error(
      "SCP-09: the protected authority manifest must bind GatewayAdmin identities in every configured workload account, with no additional GatewayAdmin accounts.",
    );
  }

  const body = {
    Version: "2012-10-17",
    Statement: [
      ...principalEntityDenyStatements(
        "DenyGatewayMutationExceptPlatformAdmin",
        [
          "bedrock-agentcore:UpdateGateway",
          "bedrock-agentcore:DeleteGateway",
          "bedrock-agentcore:CreateGatewayTarget",
          "bedrock-agentcore:UpdateGatewayTarget",
          "bedrock-agentcore:DeleteGatewayTarget",
          "bedrock-agentcore:SynchronizeGatewayTargets",
          "bedrock-agentcore:TagResource",
          "bedrock-agentcore:UntagResource",
        ],
        ["arn:aws:bedrock-agentcore:*:*:gateway/*"],
        admins,
        { awsServiceExempt: true },
      ),
      // LIVE-FOUND GAP (IAM evaluator, 2026-09-25): a create call has no
      // Gateway ARN yet and authorizes against "*", so CreateGateway inside
      // the gateway-scoped statement above never matched — any principal
      // could create a rogue Gateway. It gets its own "*" statement; the
      // action is Gateway-specific, so "*" widens nothing else.
      ...principalEntityDenyStatements(
        "DenyGatewayCreationExceptPlatformAdmin",
        ["bedrock-agentcore:CreateGateway"],
        ["*"],
        admins,
        { awsServiceExempt: true },
      ),
      // Policy writes authorize against the engine and, for update/delete,
      // the nested policy ARN. ManageResourceScopedPolicy instead evaluates
      // the Gateway ARN. Scope both forms in the same identity gate; the
      // independent Gateway mutation gate still reserves its tags to admins.
      ...principalEntityDenyStatements(
        "NativePolicy",
        [
          "bedrock-agentcore:CreatePolicy",
          "bedrock-agentcore:UpdatePolicy",
          "bedrock-agentcore:DeletePolicy",
          "bedrock-agentcore:UpdatePolicyEngine",
          "bedrock-agentcore:DeletePolicyEngine",
          "bedrock-agentcore:ManageResourceScopedPolicy",
          "bedrock-agentcore:TagResource",
          "bedrock-agentcore:UntagResource",
        ],
        [
          "arn:aws:bedrock-agentcore:*:*:policy-engine/*",
          "arn:aws:bedrock-agentcore:*:*:gateway/*",
        ],
        policyControllers,
        { awsServiceExempt: true },
      ),
      // These permissions do not support resource-level authorization.
      ...principalEntityDenyStatements(
        "NativeAdmin",
        [
          "bedrock-agentcore:CreatePolicyEngine",
          "bedrock-agentcore:ManageAdminPolicy",
        ],
        ["*"],
        policyControllers,
        { awsServiceExempt: true },
      ),
    ],
  };

  const definition = toScpDefinition(
    "scp-09",
    "AgenticAI-SCP-09-GatewayMutationLockdown",
    "Only protected, exact ARN and RoleId-bound authorities may mutate AgentCore Gateways and their native Cedar policy resources.",
    body,
  );
  if (definition.bodyJson.length > SCP_BODY_SOFT_LIMIT) {
    throw new Error(
      "SCP-09: exact enrolled authorities exceed the policy size budget; reduce the governed workload/controller scope before deployment.",
    );
  }
  return definition;
}
