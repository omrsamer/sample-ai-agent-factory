/**
 * Native Policy Engine attack/control contracts. The bounded evaluator proves
 * rendered IAM deny semantics; deployed service context still needs acceptance.
 */
import { authorityFixture } from "../../../tests/fixtures/protected-authority";
import {
  renderProtectedAuthorityStatements,
  validateProtectedAuthorityManifest,
  type AuthorityStatement,
} from "./protected-authority";
import { scp09GatewayMutationLockdown } from "./scps/scp-09-gateway-mutation-lockdown";
import { SCP_BODY_SOFT_LIMIT } from "./scps";

const ACCOUNT = "333333333333";
const ENGINE = `arn:aws:bedrock-agentcore:us-west-2:${ACCOUNT}:policy-engine/approved-engine`;
const POLICY = `${ENGINE}/policy/approved-policy`;
const GATEWAY = `arn:aws:bedrock-agentcore:us-west-2:${ACCOUNT}:gateway/authority-fixture-gateway`;

function enrolled(): any {
  const manifest: any = structuredClone(
    authorityFixture({ governedAccountIds: [ACCOUNT] }),
  );
  const prefix = `cell-${ACCOUNT}`;
  manifest.resources.push(
    {
      id: "native-key",
      kind: "kms",
      arn: `arn:aws:kms:us-west-2:${ACCOUNT}:key/11111111-2222-4333-8444-555555555555`,
      controllerIds: [`${prefix}-executor`],
      dependsOnIds: [],
      configurationSha256: "a".repeat(64),
      documentSha256: "b".repeat(64),
    },
    {
      id: "native-engine",
      kind: "agentcore-policy-engine",
      arn: ENGINE,
      controllerIds: [`${prefix}-executor`],
      dependsOnIds: [`${prefix}-stack`, "native-key"],
      configurationSha256: "c".repeat(64),
    },
    {
      id: "native-policy",
      kind: "agentcore-policy",
      arn: POLICY,
      controllerIds: [`${prefix}-executor`],
      dependsOnIds: ["native-engine"],
      configurationSha256: "d".repeat(64),
      documentSha256: "e".repeat(64),
    },
  );
  manifest.resources
    .find((resource: any) => resource.kind === "gateway")
    .dependsOnIds.push("native-engine", "native-policy");
  return manifest;
}

function matches(pattern: string, value: string): boolean {
  return new RegExp(
    `^${pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*")}$`,
  ).test(value);
}

function denies(
  statements: readonly AuthorityStatement[],
  action: string,
  resource: string,
  arn: string,
  entity: string,
): boolean {
  const list = (value: unknown): string[] =>
    typeof value === "string" ? [value] : (value as string[]);
  return statements.some((statement: any) => {
    if (!list(statement.Action).some((pattern) => matches(pattern, action)))
      return false;
    if (!list(statement.Resource).some((pattern) => matches(pattern, resource)))
      return false;
    const condition = statement.Condition ?? {};
    if (
      condition.ArnNotEquals &&
      condition.ArnNotEquals["aws:PrincipalArn"].includes(arn)
    )
      return false;
    if (
      condition.StringNotLike &&
      condition.StringNotLike["aws:userid"].some((pattern: string) =>
        matches(pattern, entity),
      )
    )
      return false;
    return true;
  });
}

describe("native policy authority", () => {
  it("closes existing Policy Engine deletion through an ordinary member-admin IAM grant", () => {
    const manifest = authorityFixture({ governedAccountIds: [ACCOUNT] });
    const statements = scp09GatewayMutationLockdown({
      workloadAccountIds: [ACCOUNT],
      protectedAuthorityManifest: manifest,
    }).body.Statement as AuthorityStatement[];
    expect(
      denies(
        statements,
        "bedrock-agentcore:DeletePolicy",
        POLICY,
        `arn:aws:iam::${ACCOUNT}:role/WorkloadAdministrator`,
        "AROA99999999999999999:attacker",
      ),
    ).toBe(true);
    const admin = manifest.roles.find((role) => role.purposes.includes("gateway-admin"))!;
    expect(
      denies(
        statements,
        "bedrock-agentcore:UpdateGateway",
        GATEWAY,
        admin.arn,
        `${admin.roleId}:approved`,
      ),
    ).toBe(false);
  });
  it("denies deletion of a legacy engine even without native manifest records", () => {
    const manifest = authorityFixture({ governedAccountIds: [ACCOUNT] });
    const statements = scp09GatewayMutationLockdown({
      workloadAccountIds: [ACCOUNT],
      protectedAuthorityManifest: manifest,
    }).body.Statement as AuthorityStatement[];
    expect(
      denies(
        statements,
        "bedrock-agentcore:DeletePolicyEngine",
        ENGINE,
        `arn:aws:iam::${ACCOUNT}:role/WorkloadAdministrator`,
        "AROA99999999999999999:attacker",
      ),
    ).toBe(true);
  });
  it("preserves the legitimate GatewayAdmin control through the same policy gate", () => {
    const manifest = authorityFixture({ governedAccountIds: [ACCOUNT] });
    const admin = manifest.roles.find((role) => role.purposes.includes("gateway-admin"))!;
    const statements = scp09GatewayMutationLockdown({
      workloadAccountIds: [ACCOUNT],
      protectedAuthorityManifest: manifest,
    }).body.Statement as AuthorityStatement[];
    for (const resource of [ENGINE, POLICY]) {
      expect(
        denies(
          statements,
          "bedrock-agentcore:DeletePolicy",
          resource,
          admin.arn,
          `${admin.roleId}:approved`,
        ),
      ).toBe(false);
    }
  });

  const scoped: [string, string][] = [
    ["CreatePolicy", ENGINE],
    ["UpdatePolicy", ENGINE],
    ["UpdatePolicy", POLICY],
    ["DeletePolicy", ENGINE],
    ["DeletePolicy", POLICY],
    ["UpdatePolicyEngine", ENGINE],
    ["DeletePolicyEngine", ENGINE],
    ["TagResource", ENGINE],
    ["UntagResource", ENGINE],
    ["CreatePolicyEngine", "*"],
    ["ManageAdminPolicy", "*"],
    ["ManageResourceScopedPolicy", GATEWAY],
  ];

  it.each(scoped)("denies a workload IAM administrator's %s on %s", (action, resource) => {
    const manifest = enrolled();
    const statements = scp09GatewayMutationLockdown({
      workloadAccountIds: [ACCOUNT],
      protectedAuthorityManifest: manifest,
    }).body.Statement as AuthorityStatement[];
    expect(
      denies(
        statements,
        `bedrock-agentcore:${action}`,
        resource,
        `arn:aws:iam::${ACCOUNT}:role/WorkloadAdministrator`,
        "AROA99999999999999999:attacker",
      ),
    ).toBe(true);
  });

  it.each(scoped)("retains an enrolled CFN controller's %s on %s", (action, resource) => {
    const manifest = enrolled();
    const controller = manifest.roles.find((role: any) =>
      role.id.endsWith("-executor"),
    );
    const statements = scp09GatewayMutationLockdown({
      workloadAccountIds: [ACCOUNT],
      protectedAuthorityManifest: manifest,
    }).body.Statement as AuthorityStatement[];
    expect(
      denies(
        statements,
        `bedrock-agentcore:${action}`,
        resource,
        controller.arn,
        `${controller.roleId}:approved`,
      ),
    ).toBe(false);
    expect(
      denies(
        statements,
        `bedrock-agentcore:${action}`,
        resource,
        controller.arn,
        "AROA99999999999999999:recreated",
      ),
    ).toBe(true);
  });

  it("also fences scoped policy and Gateway resource-policy writes in the exact graph", () => {
    const manifest = enrolled();
    const controller = manifest.roles.find((role: any) =>
      role.id.endsWith("-executor"),
    );
    const statements = renderProtectedAuthorityStatements(manifest, ACCOUNT);
    for (const [action, resource] of scoped.filter(
      ([action]) => !["CreatePolicyEngine", "ManageAdminPolicy"].includes(action),
    )) {
      expect(
        denies(
          statements,
          `bedrock-agentcore:${action}`,
          resource,
          controller.arn,
          `${controller.roleId}:approved`,
        ),
      ).toBe(false);
      expect(
        denies(
          statements,
          `bedrock-agentcore:${action}`,
          resource,
          controller.arn,
          "AROA99999999999999999:recreated",
        ),
      ).toBe(true);
    }
    for (const action of ["PutResourcePolicy", "DeleteResourcePolicy"]) {
      expect(
        denies(
          statements,
          `bedrock-agentcore:${action}`,
          GATEWAY,
          `arn:aws:iam::${ACCOUNT}:role/WorkloadAdministrator`,
          "AROA99999999999999999:attacker",
        ),
      ).toBe(true);
    }
  });

  it("keeps Gateway configuration authority separate from native CFN policy authority", () => {
    const manifest = enrolled();
    const controller = manifest.roles.find((role: any) =>
      role.id.endsWith("-executor"),
    );
    const statements = scp09GatewayMutationLockdown({
      workloadAccountIds: [ACCOUNT],
      protectedAuthorityManifest: manifest,
    }).body.Statement as AuthorityStatement[];
    for (const action of ["CreateGateway", "UpdateGateway", "DeleteGateway"]) {
      expect(
        denies(
          statements,
          `bedrock-agentcore:${action}`,
          action === "CreateGateway" ? "*" : GATEWAY,
          controller.arn,
          `${controller.roleId}:approved`,
        ),
      ).toBe(true);
    }
    expect(
      denies(
        statements,
        "bedrock-agentcore:InvokeAgentRuntime",
        `arn:aws:bedrock-agentcore:us-west-2:${ACCOUNT}:runtime/unrelated`,
        controller.arn,
        `${controller.roleId}:approved`,
      ),
    ).toBe(false);
  });

  it("does not let another workstream's enrolled controller mutate this engine", () => {
    const manifest = enrolled();
    const otherAccount = "444444444444";
    const other: any = structuredClone(
      authorityFixture({ governedAccountIds: [otherAccount] }),
    );
    for (const [index, role] of other.roles.entries()) {
      role.roleId = `AROA${String(100 + index).padStart(17, "0")}`;
    }
    manifest.governedAccountIds.push(otherAccount);
    manifest.roles.push(...other.roles.filter((role: any) => role.id !== "central-owner"));
    manifest.resources.push(...other.resources);
    const controller = other.roles.find((role: any) => role.id.endsWith("-executor"))!;
    const otherKey = {
      ...manifest.resources.find((resource: any) => resource.id === "native-key"),
      id: "other-native-key",
      arn: `arn:aws:kms:us-west-2:${otherAccount}:key/11111111-2222-4333-8444-555555555555`,
      controllerIds: [controller.id],
    };
    manifest.resources.push(otherKey, {
      ...manifest.resources.find((resource: any) => resource.id === "native-engine"),
      id: "other-native-engine",
      arn: ENGINE.replace(ACCOUNT, otherAccount),
      controllerIds: [controller.id],
      dependsOnIds: [`cell-${otherAccount}-stack`, otherKey.id],
    });
    const business = scp09GatewayMutationLockdown({
      workloadAccountIds: [ACCOUNT, otherAccount],
      protectedAuthorityManifest: manifest,
    }).body.Statement as AuthorityStatement[];
    // Both enrolled controllers may pass the business identity gate, but the
    // account's exact-resource guards enforce the particular engine owner.
    expect(
      denies(
        business,
        "bedrock-agentcore:DeletePolicy",
        POLICY,
        controller.arn,
        `${controller.roleId}:approved`,
      ),
    ).toBe(false);
    const guards = renderProtectedAuthorityStatements(manifest, ACCOUNT);
    for (const [action, resource] of [
      ["DeletePolicy", POLICY],
      ["DeletePolicy", ENGINE],
      ["DeletePolicyEngine", ENGINE],
      ["ManageResourceScopedPolicy", GATEWAY],
    ]) {
      expect(
        denies(
          guards,
          `bedrock-agentcore:${action}`,
          resource,
          controller.arn,
          `${controller.roleId}:approved`,
        ),
      ).toBe(true);
    }
  });

  it("keeps the default multi-account set with native CFN controllers inside the SCP budget", () => {
    const manifest: any = structuredClone(authorityFixture());
    for (const account of manifest.governedAccountIds) {
      const controller = `cell-${account}-executor`;
      const key = `native-key-${account}`;
      const engine = `native-engine-${account}`;
      const policy = `native-policy-${account}`;
      manifest.resources.push(
        {
          id: key,
          kind: "kms",
          arn: `arn:aws:kms:us-west-2:${account}:key/11111111-2222-4333-8444-555555555555`,
          controllerIds: [controller],
          dependsOnIds: [],
          configurationSha256: "a".repeat(64),
          documentSha256: "b".repeat(64),
        },
        {
          id: engine,
          kind: "agentcore-policy-engine",
          arn: ENGINE.replace(ACCOUNT, account),
          controllerIds: [controller],
          dependsOnIds: [`cell-${account}-stack`, key],
          configurationSha256: "c".repeat(64),
        },
        {
          id: policy,
          kind: "agentcore-policy",
          arn: POLICY.replace(ACCOUNT, account),
          controllerIds: [controller],
          dependsOnIds: [engine],
          configurationSha256: "d".repeat(64),
          documentSha256: "e".repeat(64),
        },
      );
      manifest.resources
        .find((resource: any) => resource.id === `cell-${account}-gateway`)
        .dependsOnIds.push(engine, policy);
    }
    expect(
      scp09GatewayMutationLockdown({
        workloadAccountIds: manifest.governedAccountIds,
        protectedAuthorityManifest: manifest,
      }).bodyJson.length,
    ).toBeLessThanOrEqual(SCP_BODY_SOFT_LIMIT);
  });

  it("fails closed before deploying an oversized exact-authority business policy", () => {
    const accounts = Array.from({ length: 16 }, (_, index) => String(10 + index).padStart(12, "0"));
    const manifest = authorityFixture({ governedAccountIds: accounts });
    expect(() =>
      scp09GatewayMutationLockdown({
        workloadAccountIds: accounts,
        protectedAuthorityManifest: manifest,
      }),
    ).toThrow(/SCP-09:.*size budget/);
  });

  it.each([
    "key",
    "stack",
    "engine",
    "controllers",
    "document",
    "arn",
  ])("rejects incomplete native enrollment: %s", (mutation) => {
    const manifest = enrolled();
    const engine = manifest.resources.find((resource: any) => resource.id === "native-engine");
    const policy = manifest.resources.find((resource: any) => resource.id === "native-policy");
    if (mutation === "key") engine.dependsOnIds = engine.dependsOnIds.slice(0, 1);
    else if (mutation === "stack") engine.dependsOnIds = ["native-key"];
    else if (mutation === "engine") policy.dependsOnIds = [];
    else if (mutation === "controllers") policy.controllerIds = ["central-owner"];
    else if (mutation === "document") delete policy.documentSha256;
    else policy.arn = policy.arn.replace("/policy/", "/policies/");
    expect(() => validateProtectedAuthorityManifest(manifest)).toThrow();
  });
});
