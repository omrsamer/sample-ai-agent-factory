/**
 * Explicit, reviewed identity and controller graph for SCP exemptions.
 *
 * An ARN identifies a role name; RoleId identifies the actual role entity.
 * Every exemption therefore has two independent deny gates. The lifecycle
 * and execution graph is rendered into organization-enforced protection,
 * rather than accepting a caller assertion that protection already exists.
 *
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: MIT-0
 */

export type ProtectedAuthorityPurpose =
  | "mantle"
  | "gateway-admin"
  | "telemetry"
  | "registry"
  | "guardrail-admin"
  | "gateway-invoker"
  | "controller";

export type ProtectedAuthorityResourceKind =
  | "policy"
  | "lambda"
  | "lambda-event-source-mapping"
  | "stack"
  | "stack-set"
  | "gateway"
  | "agentcore-policy-engine"
  | "agentcore-policy"
  | "pipeline"
  | "build"
  | "s3-bucket"
  | "s3-object"
  | "ecr"
  | "kms"
  | "ssm"
  | "secret"
  | "connection"
  | "layer"
  | "state-machine";

export interface ProtectedAuthorityRole {
  readonly id: string;
  readonly arn: string;
  readonly roleId: string;
  readonly purposes: readonly ProtectedAuthorityPurpose[];
  readonly lifecycleControllerIds: readonly string[];
  readonly passRoleControllerIds?: readonly string[];
  readonly policyResourceIds: readonly string[];
  readonly consumerResourceIds: readonly string[];
  readonly trustPolicySha256: string;
  readonly inlinePolicySha256: Readonly<Record<string, string>>;
  readonly attachedPolicyArns: readonly string[];
  readonly permissionsBoundaryArn?: string;
}

export interface ProtectedAuthorityResource {
  readonly id: string;
  readonly kind: ProtectedAuthorityResourceKind;
  readonly arn: string;
  readonly controllerIds: readonly string[];
  readonly invokerIds?: readonly string[];
  readonly dependsOnIds: readonly string[];
  readonly accountId?: string;
  readonly configurationSha256?: string;
  readonly documentSha256?: string;
  readonly policyId?: string;
  readonly defaultVersionId?: string;
  readonly executionRoleArn?: string;
  readonly codeSha256?: string;
  readonly versionId?: string;
}

export interface ProtectedAuthorityManifest {
  readonly schemaVersion: 1;
  readonly organizationId: string;
  readonly managementAccountId: string;
  readonly trustedControlAccountIds: readonly string[];
  readonly governedAccountIds: readonly string[];
  readonly epoch: string;
  readonly roles: readonly ProtectedAuthorityRole[];
  readonly resources: readonly ProtectedAuthorityResource[];
}

export type AuthorityStatement = Record<string, unknown>;

const PURPOSES: readonly ProtectedAuthorityPurpose[] = [
  "mantle",
  "gateway-admin",
  "telemetry",
  "registry",
  "guardrail-admin",
  "gateway-invoker",
  "controller",
];
const KINDS: readonly ProtectedAuthorityResourceKind[] = [
  "policy",
  "lambda",
  "lambda-event-source-mapping",
  "stack",
  "stack-set",
  "gateway",
  "agentcore-policy-engine",
  "agentcore-policy",
  "pipeline",
  "build",
  "s3-bucket",
  "s3-object",
  "ecr",
  "kms",
  "ssm",
  "secret",
  "connection",
  "layer",
  "state-machine",
];
const ACCOUNT = /^\d{12}$/;
const DIGEST = /^[a-f0-9]{64}$/;
const ROLE_ARN = /^arn:aws:iam::(\d{12}):role\/([A-Za-z0-9+=,.@_/-]+)$/;
const POLICY_ARN = /^arn:aws:iam::(\d{12}|aws):policy\/[A-Za-z0-9+=,.@_/-]+$/;
const ID = /^[a-z][a-z0-9-]{0,63}$/;

function requireValue(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(`ProtectedAuthorityManifest: ${message}`);
}

function record(raw: unknown, label: string): Record<string, unknown> {
  requireValue(
    typeof raw === "object" && raw !== null && !Array.isArray(raw),
    `${label} must be an object`,
  );
  return raw as Record<string, unknown>;
}

function keys(
  raw: Record<string, unknown>,
  allowed: readonly string[],
  label: string,
): void {
  requireValue(
    Object.keys(raw).every((key) => allowed.includes(key)),
    `${label} contains an unknown field`,
  );
}

function strings(
  raw: unknown,
  label: string,
  allowEmpty = true,
): readonly string[] {
  requireValue(
    Array.isArray(raw) && raw.every((value) => typeof value === "string"),
    `${label} must be an array of strings`,
  );
  requireValue(allowEmpty || raw.length > 0, `${label} must not be empty`);
  requireValue(
    new Set(raw).size === raw.length,
    `${label} contains duplicates`,
  );
  return raw;
}

function roleAccount(arn: string): string {
  const match = ROLE_ARN.exec(arn);
  requireValue(
    match &&
      match[2].split("/").every(Boolean) &&
      match[2].split("/").at(-1)!.length <= 64,
    `role ARN must be exact: ${arn}`,
  );
  return match[1];
}

function resourceAccount(resource: ProtectedAuthorityResource): string {
  if (resource.kind === "s3-bucket" || resource.kind === "s3-object") {
    requireValue(
      typeof resource.accountId === "string" &&
        ACCOUNT.test(resource.accountId),
      `${resource.id} needs an explicit S3 owner accountId`,
    );
    return resource.accountId;
  }
  return resource.arn.split(":")[4];
}

function validateResourceArn(resource: ProtectedAuthorityResource): void {
  requireValue(
    typeof resource.arn === "string" && !/[*?${}\s]/.test(resource.arn),
    `${resource.id} ARN must be exact and contain no wildcards or tokens`,
  );
  const regional = (service: string, suffix: string) =>
    new RegExp(
      `^arn:aws:${service}:[a-z]{2}(?:-[a-z0-9]+)+-\\d:\\d{12}:${suffix}$`,
    ).test(resource.arn);
  const valid: Record<ProtectedAuthorityResourceKind, boolean> = {
    policy: /^arn:aws:iam::\d{12}:policy\/[A-Za-z0-9+=,.@_/-]+$/.test(
      resource.arn,
    ),
    lambda: regional("lambda", "function:[A-Za-z0-9_-]+"),
    "lambda-event-source-mapping": regional(
      "lambda",
      "event-source-mapping:[a-f0-9-]+",
    ),
    stack: regional("cloudformation", "stack/[A-Za-z][A-Za-z0-9-]*/[a-f0-9-]+"),
    "stack-set": regional(
      "cloudformation",
      "stackset/[A-Za-z][A-Za-z0-9-]*:[a-f0-9-]+",
    ),
    gateway: regional("bedrock-agentcore", "gateway/[A-Za-z0-9_-]+"),
    "agentcore-policy-engine": regional(
      "bedrock-agentcore",
      "policy-engine/[A-Za-z0-9_-]+",
    ),
    "agentcore-policy": regional(
      "bedrock-agentcore",
      "policy-engine/[A-Za-z0-9_-]+/policy/[A-Za-z0-9_-]+",
    ),
    pipeline: regional("codepipeline", "[A-Za-z0-9_.@-]+"),
    build: regional("codebuild", "project/[A-Za-z0-9_-]+"),
    "s3-bucket": /^arn:aws:s3:::[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(
      resource.arn,
    ),
    "s3-object":
      /^arn:aws:s3:::[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\/[^\s*?${}]+$/.test(
        resource.arn,
      ),
    ecr: regional("ecr", "repository/[a-z0-9][a-z0-9._/-]+"),
    kms: regional("kms", "key/[a-f0-9-]+"),
    ssm: regional("ssm", "parameter/[A-Za-z0-9_.\\/-]+"),
    secret: regional("secretsmanager", "secret:[A-Za-z0-9/_+=.@-]+"),
    connection: regional(
      "(?:codeconnections|codestar-connections)",
      "connection/[a-f0-9-]+",
    ),
    layer: regional("lambda", "layer:[A-Za-z0-9_-]+:\\d+"),
    "state-machine": regional("states", "stateMachine:[A-Za-z0-9_-]+"),
  };
  requireValue(
    valid[resource.kind],
    `${resource.id} ARN does not match kind ${resource.kind}`,
  );
}

/**
 * Validates syntax and the complete declared protection graph. The separate
 * read-only verifier reconciles this declaration with actual AWS inventory.
 */
export function validateProtectedAuthorityManifest(
  raw: unknown,
): ProtectedAuthorityManifest {
  const object = record(raw, "manifest");
  keys(
    object,
    [
      "schemaVersion",
      "organizationId",
      "managementAccountId",
      "trustedControlAccountIds",
      "governedAccountIds",
      "epoch",
      "roles",
      "resources",
    ],
    "manifest",
  );
  requireValue(object.schemaVersion === 1, "schemaVersion must be 1");
  requireValue(
    typeof object.organizationId === "string" &&
      /^o-[a-z0-9]{10,32}$/.test(object.organizationId),
    "organizationId must be exact",
  );
  requireValue(
    typeof object.managementAccountId === "string" &&
      ACCOUNT.test(object.managementAccountId),
    "managementAccountId must be exact",
  );
  requireValue(
    typeof object.epoch === "string" &&
      /^[A-Za-z0-9_.-]{1,128}$/.test(object.epoch),
    "epoch must identify the approved inventory revision",
  );
  const governed = strings(
    object.governedAccountIds,
    "governedAccountIds",
    false,
  );
  const trusted = strings(
    object.trustedControlAccountIds,
    "trustedControlAccountIds",
  );
  requireValue(
    [...governed, ...trusted].every((account) => ACCOUNT.test(account)),
    "account IDs must be exact 12-digit values",
  );
  requireValue(
    !governed.includes(object.managementAccountId) &&
      trusted.every((account) => !governed.includes(account)),
    "trusted authority roots must be outside governed member accounts",
  );
  requireValue(
    Array.isArray(object.roles) &&
      object.roles.length > 0 &&
      object.roles.length <= 64,
    "roles must contain 1–64 reviewed records",
  );
  requireValue(
    Array.isArray(object.resources) &&
      object.resources.length > 0 &&
      object.resources.length <= 256,
    "resources must contain 1–256 reviewed records",
  );
  const manifest = object as unknown as ProtectedAuthorityManifest;
  const roles = new Map<string, ProtectedAuthorityRole>();
  const resources = new Map<string, ProtectedAuthorityResource>();
  const allAccounts = new Set([
    ...governed,
    ...trusted,
    manifest.managementAccountId,
  ]);
  const roleArns = new Set<string>();
  const roleIds = new Set<string>();
  for (const role of manifest.roles) {
    const value = record(role, "role");
    keys(
      value,
      [
        "id",
        "arn",
        "roleId",
        "purposes",
        "lifecycleControllerIds",
        "passRoleControllerIds",
        "policyResourceIds",
        "consumerResourceIds",
        "trustPolicySha256",
        "inlinePolicySha256",
        "attachedPolicyArns",
        "permissionsBoundaryArn",
      ],
      "role",
    );
    requireValue(
      typeof role.id === "string" && ID.test(role.id) && !roles.has(role.id),
      "role IDs must be unique stable names",
    );
    requireValue(
      typeof role.arn === "string" &&
        allAccounts.has(roleAccount(role.arn)) &&
        !roleArns.has(role.arn),
      `${role.id} role ARN has an unapproved account or duplicate`,
    );
    requireValue(
      !role.arn.includes(":role/aws-service-role/"),
      `${role.id} cannot use an SCP-unrestricted service-linked role as protected authority`,
    );
    requireValue(
      typeof role.roleId === "string" &&
        /^AROA[A-Z0-9]{17}$/.test(role.roleId) &&
        !roleIds.has(role.roleId),
      `${role.id} requires its unique live IAM RoleId`,
    );
    requireValue(
      strings(role.purposes, `${role.id}.purposes`, false).every((purpose) =>
        PURPOSES.includes(purpose as ProtectedAuthorityPurpose),
      ),
      `${role.id} has an unknown purpose`,
    );
    strings(role.lifecycleControllerIds, `${role.id}.lifecycleControllerIds`);
    if (role.passRoleControllerIds !== undefined)
      strings(role.passRoleControllerIds, `${role.id}.passRoleControllerIds`);
    strings(role.policyResourceIds, `${role.id}.policyResourceIds`);
    strings(role.consumerResourceIds, `${role.id}.consumerResourceIds`);
    requireValue(
      typeof role.trustPolicySha256 === "string" &&
        DIGEST.test(role.trustPolicySha256),
      `${role.id} needs an approved trust policy digest`,
    );
    const inline = record(
      role.inlinePolicySha256,
      `${role.id}.inlinePolicySha256`,
    );
    requireValue(
      Object.entries(inline).every(
        ([name, digest]) =>
          /^[\w+=,.@-]{1,128}$/.test(name) &&
          typeof digest === "string" &&
          DIGEST.test(digest),
      ),
      `${role.id} inline policy digests are invalid`,
    );
    requireValue(
      strings(role.attachedPolicyArns, `${role.id}.attachedPolicyArns`).every(
        (arn) => POLICY_ARN.test(arn),
      ),
      `${role.id} attached policies must be exact ARNs`,
    );
    requireValue(
      role.permissionsBoundaryArn === undefined ||
        POLICY_ARN.test(role.permissionsBoundaryArn),
      `${role.id} boundary must be an exact policy ARN`,
    );
    roles.set(role.id, role);
    roleArns.add(role.arn);
    roleIds.add(role.roleId);
  }
  const resourceArns = new Set<string>();
  for (const resource of manifest.resources) {
    const value = record(resource, "resource");
    keys(
      value,
      [
        "id",
        "kind",
        "arn",
        "controllerIds",
        "invokerIds",
        "dependsOnIds",
        "accountId",
        "configurationSha256",
        "documentSha256",
        "policyId",
        "defaultVersionId",
        "executionRoleArn",
        "codeSha256",
        "versionId",
      ],
      "resource",
    );
    requireValue(
      typeof resource.id === "string" &&
        ID.test(resource.id) &&
        !roles.has(resource.id) &&
        !resources.has(resource.id),
      "resource IDs must be globally unique stable names",
    );
    requireValue(
      KINDS.includes(resource.kind),
      `${resource.id} has an unsupported resource kind`,
    );
    validateResourceArn(resource);
    requireValue(
      allAccounts.has(resourceAccount(resource)) &&
        !resourceArns.has(resource.arn),
      `${resource.id} has an unapproved account or duplicate ARN`,
    );
    strings(resource.controllerIds, `${resource.id}.controllerIds`, false);
    if (resource.invokerIds !== undefined) {
      requireValue(
        resource.kind === "gateway" || resource.kind === "lambda",
        `${resource.id} invokerIds apply only to Gateway or Lambda resources`,
      );
      strings(resource.invokerIds, `${resource.id}.invokerIds`, false);
    }
    strings(resource.dependsOnIds, `${resource.id}.dependsOnIds`);
    if (resource.kind !== "policy")
      requireValue(
        typeof resource.configurationSha256 === "string" &&
          DIGEST.test(resource.configurationSha256),
        `${resource.id} needs an approved configuration digest`,
      );
    if (
      ["policy", "agentcore-policy", "stack", "kms", "s3-bucket"].includes(
        resource.kind,
      )
    )
      requireValue(
        typeof resource.documentSha256 === "string" &&
          DIGEST.test(resource.documentSha256),
        `${resource.id} needs an approved document digest`,
      );
    if (resource.kind === "policy") {
      requireValue(
        typeof resource.policyId === "string" &&
          /^ANPA[A-Z0-9]{17}$/.test(resource.policyId),
        `${resource.id} needs its live policy ID`,
      );
      requireValue(
        typeof resource.defaultVersionId === "string" &&
          /^v[1-9]\d*$/.test(resource.defaultVersionId),
        `${resource.id} needs its approved default policy version`,
      );
    }
    if (resource.kind === "lambda")
      requireValue(
        typeof resource.codeSha256 === "string" &&
          /^[A-Za-z0-9+/]{43}=$/.test(resource.codeSha256),
        `${resource.id} needs its approved Lambda code digest`,
      );
    if (resource.executionRoleArn !== undefined)
      requireValue(
        roleArns.has(resource.executionRoleArn),
        `${resource.id} execution role is outside the protected graph`,
      );
    resources.set(resource.id, resource);
    resourceArns.add(resource.arn);
  }
  function controllers(ids: readonly string[], label: string): void {
    requireValue(
      ids.every((id) => roles.has(id)),
      `${label} has an unknown controller`,
    );
  }
  const visitedRoles = new Set<string>();
  function visitRole(id: string, path: Set<string>): void {
    requireValue(!path.has(id), `controller graph is cyclic at ${id}`);
    if (visitedRoles.has(id)) return;
    const role = roles.get(id)!;
    const account = roleAccount(role.arn);
    if (role.lifecycleControllerIds.length === 0) {
      requireValue(
        !governed.includes(account) &&
          (trusted.includes(account) ||
            account === manifest.managementAccountId),
        `${id} has no central trusted lifecycle authority`,
      );
    } else {
      requireValue(
        !role.lifecycleControllerIds.includes(id),
        `${id} cannot control its own IAM lifecycle`,
      );
      for (const controller of role.lifecycleControllerIds)
        visitRole(controller, new Set([...path, id]));
    }
    visitedRoles.add(id);
  }
  for (const role of manifest.roles) {
    controllers(role.lifecycleControllerIds, role.id);
    controllers(
      role.passRoleControllerIds ?? role.lifecycleControllerIds,
      role.id,
    );
  }
  for (const role of manifest.roles) visitRole(role.id, new Set());
  const visitedResources = new Set<string>();
  function visitResource(id: string, path: Set<string>): void {
    requireValue(!path.has(id), `resource dependency graph is cyclic at ${id}`);
    if (visitedResources.has(id)) return;
    const resource = resources.get(id)!;
    for (const dependency of resource.dependsOnIds)
      visitResource(dependency, new Set([...path, id]));
    visitedResources.add(id);
  }
  for (const resource of manifest.resources) {
    controllers(resource.controllerIds, resource.id);
    if (resource.invokerIds !== undefined)
      controllers(resource.invokerIds, `${resource.id}.invokerIds`);
    requireValue(
      resource.dependsOnIds.every((id) => resources.has(id)),
      `${resource.id} has an unknown configuration dependency`,
    );
  }
  for (const resource of manifest.resources)
    visitResource(resource.id, new Set());
  function closure(
    ids: readonly string[],
    kind: ProtectedAuthorityResourceKind,
  ): boolean {
    return ids.some((id) => {
      const resource = resources.get(id)!;
      return resource.kind === kind || closure(resource.dependsOnIds, kind);
    });
  }
  for (const role of manifest.roles) {
    requireValue(
      role.policyResourceIds.every(
        (id) => resources.get(id)?.kind === "policy",
      ),
      `${role.id} policy references are incomplete`,
    );
    const policyArns = role.policyResourceIds.map(
      (id) => resources.get(id)!.arn,
    );
    const customerPolicies = [
      ...role.attachedPolicyArns,
      ...(role.permissionsBoundaryArn ? [role.permissionsBoundaryArn] : []),
    ].filter((arn) => !arn.startsWith("arn:aws:iam::aws:"));
    requireValue(
      customerPolicies.every((arn) => policyArns.includes(arn)),
      `${role.id} customer-managed or boundary policy lacks lifecycle protection`,
    );
    requireValue(
      role.consumerResourceIds.every((id) => resources.has(id)),
      `${role.id} consumer references are incomplete`,
    );
    for (const id of role.consumerResourceIds)
      requireValue(
        resources.get(id)!.executionRoleArn === role.arn,
        `${role.id} consumer ${id} must bind its actual executionRoleArn`,
      );
    if (!governed.includes(roleAccount(role.arn))) continue;
    requireValue(
      role.consumerResourceIds.length > 0 ||
        (role.purposes.length === 1 &&
          role.purposes[0] === "gateway-invoker"),
      `${role.id} needs reviewed execution consumers`,
    );
    if (role.purposes.includes("gateway-admin"))
      requireValue(
        closure(role.consumerResourceIds, "lambda"),
        `${role.id} GatewayAdmin needs its privileged Lambda consumer`,
      );
    if (role.purposes.includes("mantle"))
      requireValue(
        closure(role.consumerResourceIds, "gateway") &&
          closure(role.consumerResourceIds, "lambda"),
        `${role.id} Mantle needs its Gateway and guardrail interceptor`,
      );
    if (
      role.purposes.some((purpose) =>
        ["gateway-admin", "mantle", "telemetry", "registry"].includes(purpose),
      )
    ) {
      requireValue(
        closure(role.consumerResourceIds, "stack"),
        `${role.id} needs its owning or stored-role CloudFormation stacks`,
      );
      requireValue(
        closure(role.consumerResourceIds, "s3-object") ||
          closure(role.consumerResourceIds, "ecr"),
        `${role.id} needs protected deployment inputs`,
      );
    }
  }
  for (const resource of manifest.resources) {
    if (
      [
        "lambda",
        "stack",
        "build",
        "pipeline",
        "gateway",
        "state-machine",
      ].includes(resource.kind)
    ) {
      requireValue(
        resource.executionRoleArn !== undefined,
        `${resource.id} needs its protected executionRoleArn`,
      );
      const role = manifest.roles.find(
        (candidate) => candidate.arn === resource.executionRoleArn,
      )!;
      requireValue(
        role.consumerResourceIds.includes(resource.id),
        `${resource.id} is missing from its role's consumer inventory`,
      );
    }
    if (resource.kind === "lambda" || resource.kind === "gateway")
      requireValue(
        closure(resource.dependsOnIds, "stack"),
        `${resource.id} needs its protected owning stack`,
      );
    if (resource.kind === "agentcore-policy-engine")
      requireValue(
        closure(resource.dependsOnIds, "stack") &&
          closure(resource.dependsOnIds, "kms"),
        `${resource.id} needs its protected owning stack and encryption key`,
      );
    if (resource.kind === "agentcore-policy") {
      const engineArn = resource.arn.split("/policy/")[0];
      const engine = manifest.resources.find(
        (candidate) =>
          candidate.kind === "agentcore-policy-engine" &&
          candidate.arn === engineArn,
      );
      requireValue(
        engine &&
          resource.dependsOnIds.includes(engine.id) &&
          JSON.stringify([...resource.controllerIds].sort()) ===
            JSON.stringify([...engine.controllerIds].sort()),
        `${resource.id} needs its exact protected engine and the same policy controllers`,
      );
    }
    if (resource.kind === "s3-object") {
      const bucketArn = resource.arn.slice(
        0,
        resource.arn.indexOf("/", "arn:aws:s3:::".length),
      );
      requireValue(
        resource.dependsOnIds.some((id) => {
          const dependency = resources.get(id)!;
          return (
            dependency.kind === "s3-bucket" &&
            dependency.arn === bucketArn &&
            resourceAccount(dependency) === resourceAccount(resource)
          );
        }),
        `${resource.id} needs its exact protected owner bucket`,
      );
    }
  }
  return manifest;
}

export function protectedRolesForPurpose(
  manifest: ProtectedAuthorityManifest,
  purpose: ProtectedAuthorityPurpose,
): readonly ProtectedAuthorityRole[] {
  return manifest.roles.filter((role) => role.purposes.includes(purpose));
}

/**
 * Independent Denies implement (not approved ARN) OR (not approved entity).
 * Combining the negative conditions in one statement would implement AND
 * and let a recreated same-name role inherit the exception.
 */
export function principalEntityDenyStatements(
  sidPrefix: string,
  actions: readonly string[],
  resources: readonly string[] | string,
  roles: readonly ProtectedAuthorityRole[],
  options: { readonly awsServiceExempt?: boolean } = {},
): readonly AuthorityStatement[] {
  for (const role of roles) {
    roleAccount(role.arn);
    requireValue(
      /^AROA[A-Z0-9]{17}$/.test(role.roleId),
      "identity gates require exact live role IDs",
    );
  }
  const common = { Effect: "Deny", Action: [...actions], Resource: resources };
  const service = options.awsServiceExempt
    ? { BoolIfExists: { "aws:PrincipalIsAWSService": "false" } }
    : {};
  if (roles.length === 0)
    return [
      {
        Sid: `${sidPrefix}NoAuthority`,
        ...common,
        ...(options.awsServiceExempt ? { Condition: service } : {}),
      },
    ];
  return [
    {
      Sid: `${sidPrefix}Arn`,
      ...common,
      Condition: {
        ArnNotEquals: {
          "aws:PrincipalArn": [
            ...new Set(roles.map((role) => role.arn)),
          ].sort(),
        },
        ...service,
      },
    },
    {
      Sid: `${sidPrefix}Entity`,
      ...common,
      Condition: {
        StringNotLike: {
          "aws:userid": [
            ...new Set(roles.map((role) => `${role.roleId}:*`)),
          ].sort(),
        },
        ...service,
      },
    },
  ];
}

const RESOURCE_ACTIONS: Readonly<
  Record<ProtectedAuthorityResourceKind, readonly string[]>
> = {
  policy: [
    "iam:CreatePolicy",
    "iam:DeletePolicy",
    "iam:CreatePolicyVersion",
    "iam:DeletePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:TagPolicy",
    "iam:UntagPolicy",
  ],
  lambda: [
    "lambda:CreateFunction",
    "lambda:DeleteFunction",
    "lambda:UpdateFunctionCode",
    "lambda:UpdateFunctionConfiguration",
    "lambda:PublishVersion",
    "lambda:CreateAlias",
    "lambda:UpdateAlias",
    "lambda:DeleteAlias",
    "lambda:AddPermission",
    "lambda:RemovePermission",
    "lambda:PutFunctionCodeSigningConfig",
    "lambda:DeleteFunctionCodeSigningConfig",
    "lambda:CreateFunctionUrlConfig",
    "lambda:UpdateFunctionUrlConfig",
    "lambda:DeleteFunctionUrlConfig",
    "lambda:TagResource",
    "lambda:UntagResource",
    "lambda:PutFunctionConcurrency",
    "lambda:DeleteFunctionConcurrency",
    "lambda:PutFunctionEventInvokeConfig",
    "lambda:UpdateFunctionEventInvokeConfig",
    "lambda:DeleteFunctionEventInvokeConfig",
  ],
  "lambda-event-source-mapping": [
    "lambda:UpdateEventSourceMapping",
    "lambda:DeleteEventSourceMapping",
  ],
  stack: [
    "cloudformation:CreateStack",
    "cloudformation:UpdateStack",
    "cloudformation:DeleteStack",
    "cloudformation:CreateChangeSet",
    "cloudformation:ExecuteChangeSet",
    "cloudformation:DeleteChangeSet",
    "cloudformation:ContinueUpdateRollback",
    "cloudformation:RollbackStack",
    "cloudformation:CancelUpdateStack",
    "cloudformation:SetStackPolicy",
    "cloudformation:UpdateTerminationProtection",
    "cloudformation:SignalResource",
    "cloudformation:CreateStackRefactor",
    "cloudformation:ExecuteStackRefactor",
    "cloudformation:RecordHandlerProgress",
    "cloudformation:SetAlias",
    "cloudformation:RemoveAlias",
  ],
  "stack-set": [
    "cloudformation:CreateStackSet",
    "cloudformation:UpdateStackSet",
    "cloudformation:DeleteStackSet",
    "cloudformation:CreateStackInstances",
    "cloudformation:UpdateStackInstances",
    "cloudformation:DeleteStackInstances",
    "cloudformation:ImportStacksToStackSet",
    "cloudformation:StopStackSetOperation",
  ],
  gateway: [
    "bedrock-agentcore:UpdateGateway",
    "bedrock-agentcore:DeleteGateway",
    "bedrock-agentcore:CreateGatewayTarget",
    "bedrock-agentcore:UpdateGatewayTarget",
    "bedrock-agentcore:DeleteGatewayTarget",
    "bedrock-agentcore:SynchronizeGatewayTargets",
    "bedrock-agentcore:TagResource",
    "bedrock-agentcore:UntagResource",
    "bedrock-agentcore:PutResourcePolicy",
    "bedrock-agentcore:DeleteResourcePolicy",
  ],
  "agentcore-policy-engine": [
    "bedrock-agentcore:CreatePolicy",
    "bedrock-agentcore:UpdatePolicy",
    "bedrock-agentcore:DeletePolicy",
    "bedrock-agentcore:UpdatePolicyEngine",
    "bedrock-agentcore:DeletePolicyEngine",
    "bedrock-agentcore:TagResource",
    "bedrock-agentcore:UntagResource",
  ],
  "agentcore-policy": [
    "bedrock-agentcore:UpdatePolicy",
    "bedrock-agentcore:DeletePolicy",
  ],
  pipeline: [
    "codepipeline:UpdatePipeline",
    "codepipeline:DeletePipeline",
    "codepipeline:StartPipelineExecution",
    "codepipeline:StopPipelineExecution",
    "codepipeline:RetryStageExecution",
    "codepipeline:DisableStageTransition",
    "codepipeline:EnableStageTransition",
    "codepipeline:PutActionRevision",
    "codepipeline:PutApprovalResult",
    "codepipeline:TagResource",
    "codepipeline:UntagResource",
  ],
  build: [
    "codebuild:UpdateProject",
    "codebuild:DeleteProject",
    "codebuild:PutResourcePolicy",
    "codebuild:DeleteResourcePolicy",
    "codebuild:UpdateProjectVisibility",
    "codebuild:StartBuild",
    "codebuild:StartBuildBatch",
    "codebuild:RetryBuild",
    "codebuild:RetryBuildBatch",
    "codebuild:StopBuild",
    "codebuild:StopBuildBatch",
    "codebuild:CreateWebhook",
    "codebuild:UpdateWebhook",
    "codebuild:DeleteWebhook",
  ],
  "s3-bucket": [
    "s3:DeleteBucket",
    "s3:PutBucketPolicy",
    "s3:DeleteBucketPolicy",
    "s3:PutBucketAcl",
    "s3:PutBucketVersioning",
    "s3:PutLifecycleConfiguration",
    "s3:PutEncryptionConfiguration",
    "s3:PutBucketPublicAccessBlock",
    "s3:PutBucketOwnershipControls",
    "s3:PutReplicationConfiguration",
    "s3:PutBucketNotification",
    "s3:PutBucketTagging",
  ],
  "s3-object": [
    "s3:PutObject",
    "s3:DeleteObject",
    "s3:DeleteObjectVersion",
    "s3:PutObjectAcl",
    "s3:PutObjectVersionAcl",
    "s3:PutObjectTagging",
    "s3:DeleteObjectTagging",
    "s3:PutObjectVersionTagging",
    "s3:DeleteObjectVersionTagging",
    "s3:RestoreObject",
  ],
  ecr: [
    "ecr:PutImage",
    "ecr:BatchDeleteImage",
    "ecr:InitiateLayerUpload",
    "ecr:UploadLayerPart",
    "ecr:CompleteLayerUpload",
    "ecr:DeleteRepository",
    "ecr:SetRepositoryPolicy",
    "ecr:DeleteRepositoryPolicy",
    "ecr:PutImageTagMutability",
    "ecr:PutLifecyclePolicy",
    "ecr:DeleteLifecyclePolicy",
    "ecr:TagResource",
    "ecr:UntagResource",
  ],
  kms: [
    "kms:PutKeyPolicy",
    "kms:CreateGrant",
    "kms:RevokeGrant",
    "kms:RetireGrant",
    "kms:ScheduleKeyDeletion",
    "kms:CancelKeyDeletion",
    "kms:DisableKey",
    "kms:DisableKeyRotation",
    "kms:EnableKeyRotation",
    "kms:UpdatePrimaryRegion",
    "kms:ReplicateKey",
    "kms:UpdateKeyDescription",
    "kms:TagResource",
    "kms:UntagResource",
  ],
  ssm: [
    "ssm:PutParameter",
    "ssm:DeleteParameter",
    "ssm:DeleteParameters",
    "ssm:LabelParameterVersion",
    "ssm:UnlabelParameterVersion",
    "ssm:AddTagsToResource",
    "ssm:RemoveTagsFromResource",
  ],
  secret: [
    "secretsmanager:PutSecretValue",
    "secretsmanager:UpdateSecret",
    "secretsmanager:UpdateSecretVersionStage",
    "secretsmanager:RotateSecret",
    "secretsmanager:CancelRotateSecret",
    "secretsmanager:DeleteSecret",
    "secretsmanager:RestoreSecret",
    "secretsmanager:PutResourcePolicy",
    "secretsmanager:DeleteResourcePolicy",
    "secretsmanager:ReplicateSecretToRegions",
    "secretsmanager:RemoveRegionsFromReplication",
    "secretsmanager:TagResource",
    "secretsmanager:UntagResource",
  ],
  connection: [
    "codeconnections:DeleteConnection",
    "codeconnections:UpdateConnectionInstallation",
    "codeconnections:TagResource",
    "codeconnections:UntagResource",
    "codestar-connections:DeleteConnection",
    "codestar-connections:UpdateConnectionInstallation",
    "codestar-connections:TagResource",
    "codestar-connections:UntagResource",
  ],
  layer: [
    "lambda:DeleteLayerVersion",
    "lambda:AddLayerVersionPermission",
    "lambda:RemoveLayerVersionPermission",
  ],
  "state-machine": [
    "states:UpdateStateMachine",
    "states:DeleteStateMachine",
    "states:DeleteStateMachineVersion",
    "states:StartExecution",
    "states:StartSyncExecution",
    "states:PublishStateMachineVersion",
    "states:CreateStateMachineAlias",
    "states:UpdateStateMachineAlias",
    "states:DeleteStateMachineAlias",
    "states:TagResource",
    "states:UntagResource",
  ],
};

const ROLE_MUTATION_ACTIONS = [
  "iam:CreateRole",
  "iam:DeleteRole",
  "iam:UpdateRole",
  "iam:UpdateRoleDescription",
  "iam:UpdateAssumeRolePolicy",
  "iam:PutRolePolicy",
  "iam:DeleteRolePolicy",
  "iam:AttachRolePolicy",
  "iam:DetachRolePolicy",
  "iam:PutRolePermissionsBoundary",
  "iam:DeleteRolePermissionsBoundary",
  "iam:TagRole",
  "iam:UntagRole",
];
const CONSUMER_SERVICES: Readonly<
  Partial<Record<ProtectedAuthorityResourceKind, string>>
> = {
  lambda: "lambda.amazonaws.com",
  stack: "cloudformation.amazonaws.com",
  gateway: "bedrock-agentcore.amazonaws.com",
  pipeline: "codepipeline.amazonaws.com",
  build: "codebuild.amazonaws.com",
  "state-machine": "states.amazonaws.com",
};

/** Render actual guards. The management assembly packs and attaches them. */
export function renderProtectedAuthorityStatements(
  raw: ProtectedAuthorityManifest,
  accountId?: string,
): readonly AuthorityStatement[] {
  const manifest = validateProtectedAuthorityManifest(raw);
  requireValue(
    accountId === undefined || manifest.governedAccountIds.includes(accountId),
    "protection target must be an exact governed member account",
  );
  const roles = new Map(manifest.roles.map((role) => [role.id, role]));
  const resources = new Map(
    manifest.resources.map((resource) => [resource.id, resource]),
  );
  const result: AuthorityStatement[] = [];
  let ordinal = 0;
  const gate = (
    actions: readonly string[],
    arns: readonly string[] | string,
    controllerIds: readonly string[],
  ) =>
    result.push(
      ...principalEntityDenyStatements(
        `Protect${++ordinal}`,
        actions,
        arns,
        controllerIds.map((id) => roles.get(id)!),
      ),
    );
  for (const role of [...manifest.roles].sort((left, right) =>
    left.id.localeCompare(right.id),
  )) {
    if (!manifest.governedAccountIds.includes(roleAccount(role.arn))) continue;
    if (accountId !== undefined && roleAccount(role.arn) !== accountId)
      continue;
    gate(ROLE_MUTATION_ACTIONS, [role.arn], role.lifecycleControllerIds);
    // No member role may directly assume a protected service/exemption role.
    // Reviewed lifecycle controllers are the sole human/CI credential path.
    gate(["sts:AssumeRole"], [role.arn], role.lifecycleControllerIds);
    const passing = role.passRoleControllerIds ?? role.lifecycleControllerIds;
    gate(["iam:PassRole"], [role.arn], passing);
    const consumers = role.consumerResourceIds.map((id) => resources.get(id)!);
    const services = [
      ...new Set(
        consumers
          .map((consumer) => CONSUMER_SERVICES[consumer.kind])
          .filter((value): value is string => value !== undefined),
      ),
    ].sort();
    result.push({
      Sid: `PassRoleService${++ordinal}`,
      Effect: "Deny",
      Action: "iam:PassRole",
      Resource: role.arn,
      ...(services.length
        ? {
            Condition: {
              StringNotEqualsIfExists: { "iam:PassedToService": services },
            },
          }
        : {}),
    });
    result.push({
      Sid: `PassRoleConsumer${++ordinal}`,
      Effect: "Deny",
      Action: "iam:PassRole",
      Resource: role.arn,
      ...(consumers.length
        ? {
            Condition: {
              ArnNotEqualsIfExists: {
                "iam:AssociatedResourceArn": consumers
                  .map((consumer) => consumer.arn)
                  .sort(),
              },
            },
          }
        : {}),
    });
  }
  for (const resource of [...manifest.resources].sort((left, right) =>
    left.id.localeCompare(right.id),
  )) {
    if (!manifest.governedAccountIds.includes(resourceAccount(resource)))
      continue;
    if (accountId !== undefined && resourceAccount(resource) !== accountId)
      continue;
    const arns = [resource.arn];
    if (resource.kind === "lambda") {
      // Alias/version credentials must not bypass the unqualified function guard.
      const unqualified = resource.arn.split(":").slice(0, 7).join(":");
      arns.push(unqualified, `${unqualified}:*`);
    }
    gate(
      RESOURCE_ACTIONS[resource.kind],
      [...new Set(arns)],
      resource.controllerIds,
    );
    if (resource.kind === "gateway" || resource.kind === "lambda") {
      // Approved callers may invoke protected services without gaining control
      // over the service configuration or its privileged execution role.
      gate(
        resource.kind === "gateway"
          ? ["bedrock-agentcore:InvokeGateway"]
          : ["lambda:InvokeFunction", "lambda:InvokeFunctionUrl"],
        [...new Set(arns)],
        resource.invokerIds ?? resource.controllerIds,
      );
    }
    if (resource.kind === "gateway") {
      // A scoped policy write authorizes against its Gateway as well as its
      // policy resources. Enrolled engine controllers may manage that policy
      // without gaining Gateway configuration or target mutation authority.
      const dependencyIds = new Set<string>();
      const visit = (id: string): void => {
        if (dependencyIds.has(id)) return;
        dependencyIds.add(id);
        resources.get(id)!.dependsOnIds.forEach(visit);
      };
      resource.dependsOnIds.forEach(visit);
      gate(
        ["bedrock-agentcore:ManageResourceScopedPolicy"],
        [resource.arn],
        [
          ...new Set([
            ...resource.controllerIds,
            ...[...dependencyIds]
              .map((id) => resources.get(id)!)
              .filter((dependency) => dependency.kind === "agentcore-policy-engine")
              .flatMap((dependency) => dependency.controllerIds),
          ]),
        ],
      );
    }
    if (resource.kind === "s3-bucket") {
      // Enrollment covers the bucket's entire artifact namespace, including
      // new content-addressed objects created by later legitimate builds.
      // A protected old object alone leaves the next build's key writable.
      gate(
        RESOURCE_ACTIONS["s3-object"],
        [`${resource.arn}/*`],
        resource.controllerIds,
      );
    }
    if (resource.kind === "build") {
      // Protected execution supports normal reviewed builds. Interactive
      // sandboxes and batch buildspec overrides have a separate stored
      // authority/input surface and cannot be activated by this enrollment.
      result.push({
        Sid: `UnsupportedBuildExecution${++ordinal}`,
        Effect: "Deny",
        Action: [
          "codebuild:StartSandbox",
          "codebuild:StartBuildBatch",
          "codebuild:RetryBuildBatch",
        ],
        Resource: resource.arn,
      });
    }
    if (resource.kind === "state-machine") {
      // Redrive authorizes the saved execution rather than the state machine.
      // Distributed Map child executions include a /MapRunLabel suffix.
      const executionArn = resource.arn.replace(
        ":stateMachine:",
        ":execution:",
      );
      gate(
        ["states:RedriveExecution"],
        [`${executionArn}:*`, `${executionArn}/*:*`],
        resource.controllerIds,
      );
    }
    if (resource.kind === "lambda") {
      // Create/UpdateEventSourceMapping authorizes against the mapping, not
      // the target function. Fence attachment using the documented key.
      for (const statement of principalEntityDenyStatements(
        `ProtectMapping${++ordinal}`,
        ["lambda:CreateEventSourceMapping", "lambda:UpdateEventSourceMapping"],
        "*",
        resource.controllerIds.map((id) => roles.get(id)!),
      )) {
        result.push({
          ...statement,
          Condition: {
            ...(statement.Condition as Record<string, unknown>),
            ArnLike: {
              "lambda:FunctionArn": [
                resource.arn.split(":").slice(0, 7).join(":"),
                `${resource.arn.split(":").slice(0, 7).join(":")}:*`,
              ],
            },
          },
        });
      }
    }
  }
  // A new service-managed StackSet has no resource ARN. Its service-linked
  // execution role is not constrained by SCPs, so governed member users
  // cannot create or operate this alternate execution route.
  const centralControllers = manifest.roles.filter(
    (role) =>
      !manifest.governedAccountIds.includes(roleAccount(role.arn)) &&
      role.purposes.includes("controller"),
  );
  gate(
    RESOURCE_ACTIONS["stack-set"],
    "*",
    centralControllers.map((role) => role.id),
  );
  return result;
}
