/**
 * SCP bypass-regression tests.
 *
 * These lock down the condition shapes introduced by the production-blocker
 * security review. Each assertion corresponds to a specific bypass that
 * slipped through the previous SCP bodies:
 *
 *   - SCP-02: `Null`-only gate allowed empty-string GuardrailIdentifier —
 *             now paired with an allow-list `ForAllValues:StringNotEquals`.
 *   - SCP-03: `StringNotEqualsIfExists` on `aws:SourceVpce` made the key's
 *             absence satisfy the condition → public calls skipped the
 *             deny — now accompanied by a `Null: aws:SourceVpce = true`
 *             twin deny.
 *   - SCP-04: same bypass / same fix as SCP-03.
 *   - Protected business exceptions: a matching mutable role name was enough
 *             to inherit authority. Exact IAM role ARN and immutable RoleId
 *             are now enforced by independent Denies.
 *
 * Business SCPs carry a `PrincipalIsAWSService=false` guard so
 * AWS-owned service principals (Config, GuardDuty, CloudTrail, …) are not
 * self-denied.
 *
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: MIT-0
 */
import {
  buildScpSet,
  SCP_BODY_SOFT_LIMIT,
} from "../../packages/organizations/src/scps/index";
import {
  allowedModelArns,
  PLATFORM_APPROVED_REGIONS,
} from "@agenticai/platform-baselines";
import { authorityFixture } from "../fixtures/protected-authority";

const PLATFORM_GUARDRAIL_ADMIN_ROLE_ARN =
  "arn:aws:iam::111111111111:role/AgenticAI-GuardrailAdmin";
const APPROVED_GUARDRAIL_IDS = [
  "arn:aws:bedrock:us-west-2:111111111111:guardrail/platformdefault",
];
const PLATFORM_ACCOUNT_ID = "222222222222";
const WORKLOAD_ACCOUNT_ID = "333333333333";
const ALLOWED_TOOL_TARGET_ARNS = [
  "arn:aws:lambda:us-west-2:333333333333:function:tool-search",
  "arn:aws:lambda:us-west-2:333333333333:function:tool-weather",
];

function renderSet(
  opts: {
    approvedGuardrailIds?: readonly string[];
    platformAccountId?: string;
    gatewayAdminWorkloadAccountIds?: readonly string[];
    allowedToolTargetArns?: readonly string[];
    protectedAuthorityManifest?: unknown;
  } = {},
) {
  return buildScpSet({
    allowedModelArns: allowedModelArns("us-west-2"),
    approvedRegions: PLATFORM_APPROVED_REGIONS,
    platformGuardrailAdminRoleArn: PLATFORM_GUARDRAIL_ADMIN_ROLE_ARN,
    approvedGuardrailIds: opts.approvedGuardrailIds,
    approvedAgentCoreVpceIds: ["vpce-0a1b2c3d4e5f60001"],
    approvedBedrockVpceIds: ["vpce-0a1b2c3d4e5f60002"],
    platformAccountId: opts.platformAccountId,
    gatewayAdminWorkloadAccountIds: opts.gatewayAdminWorkloadAccountIds,
    allowedToolTargetArns: opts.allowedToolTargetArns,
    protectedAuthorityManifest:
      "protectedAuthorityManifest" in opts
        ? opts.protectedAuthorityManifest
        : opts.gatewayAdminWorkloadAccountIds
          ? authorityFixture({
              governedAccountIds: opts.gatewayAdminWorkloadAccountIds,
            })
          : undefined,
  });
}

/**
 * IAM condition-evaluation model used by the bypass-regression tests below.
 *
 * `ArnNotLike` / `ArnLike` on `aws:PrincipalArn` treats the candidate ARN as
 * a glob-matched string (standard-globs only: `*` and `?`). These helpers
 * mirror that semantics so the regression tests do not depend on live IAM.
 */
function arnLikeMatch(pattern: string, candidate: string): boolean {
  // Escape regex metacharacters, then replace glob wildcards.
  const re = new RegExp(
    "^" +
      pattern
        .replace(/[-[\]{}()+.,\\^$|#\s]/g, "\\$&")
        .replace(/\*/g, ".*")
        .replace(/\?/g, ".") +
      "$",
  );
  return re.test(candidate);
}
function arnNotLikeFires(
  patterns: readonly string[],
  candidate: string,
): boolean {
  // Deny fires iff the candidate does NOT match ANY of the allowed patterns.
  return !patterns.some((p) => arnLikeMatch(p, candidate));
}
function arnLikeFires(patterns: readonly string[], candidate: string): boolean {
  return patterns.some((p) => arnLikeMatch(p, candidate));
}

/** Bounded IAM condition model for the rendered business identity gates. */
function principalGateDenies(
  statements: any[],
  action: string,
  context: Record<string, string>,
): boolean {
  return statements.some((statement) => {
    if (!statement.Action.includes(action)) return false;
    return Object.entries(statement.Condition ?? {}).every(([operator, values]) =>
      Object.entries(values as Record<string, string | string[]>).every(([key, raw]) => {
        const expected = [raw].flat();
        const actual = context[key];
        if (operator === "ArnNotEquals") {
          return actual === undefined || !expected.includes(actual);
        }
        if (operator === "StringNotLike") {
          return actual === undefined || !expected.some((pattern) => arnLikeMatch(pattern, actual));
        }
        if (operator === "BoolIfExists") {
          return actual === undefined || expected.includes(actual);
        }
        throw new Error(`Unexpected identity-gate operator ${operator}`);
      }),
    );
  });
}

describe("SCP bypass regression — SCP-02 (empty-string GuardrailIdentifier)", () => {
  it("with approvedGuardrailIds emits the Null gate, the ARN allow-list Deny and the empty-string twin", () => {
    const scp02 = renderSet({
      approvedGuardrailIds: APPROVED_GUARDRAIL_IDS,
    })[1];
    const parsed = scp02.body as any;

    const nullStmt = parsed.Statement.find(
      (s: any) => s.Condition?.Null?.["bedrock:GuardrailIdentifier"] === "true",
    );
    expect(nullStmt).toBeDefined();

    // ARN operators: the key is ARN-typed and may carry `<arn>:<version>`.
    // (`ForAllValues:` on this single-valued key was flagged overly
    // permissive by Access Analyzer, 2026-09-25.)
    const allowListStmt = parsed.Statement.find(
      (s: any) => s.Condition?.ArnNotLike?.["bedrock:GuardrailIdentifier"],
    );
    expect(allowListStmt).toBeDefined();
    expect(
      allowListStmt.Condition.ArnNotLike["bedrock:GuardrailIdentifier"],
    ).toEqual([APPROVED_GUARDRAIL_IDS[0], `${APPROVED_GUARDRAIL_IDS[0]}:*`]);

    // ARN operators do not match an empty value; the explicit twin closes
    // the `GuardrailIdentifier=""` bypass (live IAM evaluator, 2026-09-25).
    const emptyStmt = parsed.Statement.find(
      (s: any) => s.Condition?.StringEquals?.["bedrock:GuardrailIdentifier"] === "",
    );
    expect(emptyStmt).toBeDefined();
    expect(scp02.bodyJson).not.toContain("ForAllValues");
  });

  it("falls back to Null-only gate when approvedGuardrailIds is omitted (with warning)", () => {
    const warn = jest.spyOn(console, "warn").mockImplementation(() => {});
    try {
      const scp02 = renderSet()[1];
      const parsed = scp02.body as any;
      expect(parsed.Statement).toHaveLength(2);
      expect(
        parsed.Statement[0].Condition.Null["bedrock:GuardrailIdentifier"],
      ).toBe("true");
      expect(parsed.Statement[1].Sid).toBe("DenyDirectMantleInferenceNoAuthority");
      expect(warn).toHaveBeenCalledWith(
        expect.stringContaining("TODO-APPROVED-GUARDRAILS"),
      );
    } finally {
      warn.mockRestore();
    }
  });
});

describe("SCP bypass regression — SCP-03 (IfExists on aws:SourceVpce)", () => {
  it("emits both the StringNotEquals VPCE deny AND the Null-source-VPCE twin deny", () => {
    const scp03 = renderSet()[2];
    const parsed = scp03.body as any;

    const vpceDeny = parsed.Statement.find(
      (s: any) => s.Condition?.StringNotEquals?.["aws:SourceVpce"],
    );
    expect(vpceDeny).toBeDefined();
    // No IfExists suffix — absence must no longer skip the deny.
    expect(vpceDeny.Condition.StringNotEqualsIfExists).toBeUndefined();

    const nullDeny = parsed.Statement.find(
      (s: any) => s.Condition?.Null?.["aws:SourceVpce"] === "true",
    );
    expect(nullDeny).toBeDefined();
    expect(nullDeny.Action).toEqual(["bedrock-agentcore:*"]);
  });
});

describe("SCP bypass regression — SCP-04 (IfExists on aws:SourceVpce)", () => {
  it("emits both the StringNotEquals VPCE deny AND the Null-source-VPCE twin deny", () => {
    const scp04 = renderSet()[3];
    const parsed = scp04.body as any;

    const vpceDeny = parsed.Statement.find(
      (s: any) => s.Condition?.StringNotEquals?.["aws:SourceVpce"],
    );
    expect(vpceDeny).toBeDefined();
    expect(vpceDeny.Condition.StringNotEqualsIfExists).toBeUndefined();

    const nullDeny = parsed.Statement.find(
      (s: any) => s.Condition?.Null?.["aws:SourceVpce"] === "true",
    );
    expect(nullDeny).toBeDefined();
    expect(nullDeny.Action).toContain("bedrock:ApplyGuardrail");
  });
});

describe("SCP bypass regression — SCP-05 default API compatibility", () => {
  it("preserves the exact configured role discriminator when no protected manifest is selected", () => {
    const scp05 = renderSet()[4];
    const parsed = scp05.body as any;
    const stmt = parsed.Statement[0];
    expect(stmt.Condition.ArnNotLike).toBeDefined();
    expect(stmt.Condition.StringNotEquals).toBeUndefined();
    const arns: string[] = stmt.Condition.ArnNotLike["aws:PrincipalArn"];
    expect(arns).toEqual(
      expect.arrayContaining([
        "arn:aws:iam::111111111111:role/AgenticAI-GuardrailAdmin",
        "arn:aws:sts::111111111111:assumed-role/AgenticAI-GuardrailAdmin/*",
      ]),
    );
  });

  it("with a manifest requires both the approved admin ARN and its immutable RoleId", () => {
    const manifest = authorityFixture({ governedAccountIds: [WORKLOAD_ACCOUNT_ID] });
    const admin = manifest.roles.find((role) => role.id === "central-owner")!;
    const statements = (renderSet({ protectedAuthorityManifest: manifest })[4].body as any).Statement;
    expect(statements).toHaveLength(2);
    expect(statements.find((statement: any) => statement.Condition.ArnNotEquals)
      .Condition.ArnNotEquals["aws:PrincipalArn"]).toEqual([admin.arn]);
    expect(statements.find((statement: any) => statement.Condition.StringNotLike)
      .Condition.StringNotLike["aws:userid"]).toEqual([`${admin.roleId}:*`]);
    expect(statements.every((statement: any) =>
      !(statement.Condition.ArnNotEquals && statement.Condition.StringNotLike),
    )).toBe(true);
    for (const action of [
      "bedrock:CreateGuardrail",
      "bedrock:UpdateGuardrail",
      "bedrock:DeleteGuardrail",
      "bedrock:CreateGuardrailVersion",
    ]) {
      const legitimate: Record<string, string> = {
        "aws:PrincipalArn": admin.arn,
        "aws:userid": `${admin.roleId}:approved-session`,
        "aws:PrincipalIsAWSService": "false",
      };
      expect(principalGateDenies(statements, action, legitimate)).toBe(false);
      expect(principalGateDenies(statements, action, {
        ...legitimate,
        "aws:userid": "AROA99999999999999999:recreated-role",
      })).toBe(true);
      expect(principalGateDenies(statements, action, {
        ...legitimate,
        "aws:PrincipalArn": `${admin.arn}-lookalike`,
      })).toBe(true);
      const missingEntity = { ...legitimate };
      delete missingEntity["aws:userid"];
      expect(principalGateDenies(statements, action, missingEntity)).toBe(true);
    }
  });
});

describe("SCP bypass regression — AWS-service principal self-denial guard", () => {
  it("SCPs 02, 03, 04, 05 all carry PrincipalIsAWSService=false on every statement", () => {
    const set = renderSet({ approvedGuardrailIds: APPROVED_GUARDRAIL_IDS });
    const targets = [set[1], set[2], set[3], set[4]]; // SCP-02, 03, 04, 05
    for (const scp of targets) {
      const parsed = scp.body as any;
      for (const stmt of parsed.Statement) {
        const guard =
          stmt.Condition?.BoolIfExists?.["aws:PrincipalIsAWSService"];
        expect(guard).toBe("false");
      }
    }
  });
});

describe("SCP bypass regression — size budget", () => {
  it("every rewritten SCP body stays within the 5000-char soft limit", () => {
    const set = renderSet({
      approvedGuardrailIds: APPROVED_GUARDRAIL_IDS,
      platformAccountId: PLATFORM_ACCOUNT_ID,
      gatewayAdminWorkloadAccountIds: [WORKLOAD_ACCOUNT_ID],
      allowedToolTargetArns: ALLOWED_TOOL_TARGET_ARNS,
    });
    for (const scp of set) {
      expect(scp.bodyJson.length).toBeLessThanOrEqual(SCP_BODY_SOFT_LIMIT);
    }
  });
});

describe("SCP bypass regression — SCP-09 (Gateway mutation lockdown)", () => {
  function getScp09() {
    const set = renderSet({
      gatewayAdminWorkloadAccountIds: [WORKLOAD_ACCOUNT_ID],
    });
    const scp09 = set.find((s) => s.id === "scp-09")!;
    expect(scp09).toBeDefined();
    return scp09;
  }

  it("the exact ARN gate denies an empty principal", () => {
    // Bypass scenario: a malformed principal evaluation surfaces "" as the
    // aws:PrincipalArn value. ArnNotLike must still treat "" as not-like any
    // allowed admin ARN, so the Deny fires.
    const parsed = getScp09().body as any;
    const allowed: string[] =
      parsed.Statement[0].Condition.ArnNotEquals["aws:PrincipalArn"];
    expect(arnNotLikeFires(allowed, "")).toBe(true);
  });

  it("case-altered role forgeries fail the exact ARN gate", () => {
    // IAM ARNs are technically case-sensitive in string comparisons, but
    // ArnNotLike against the canonical spelling means a case-different forgery
    // (e.g. "AGENTICAI-d03-GATEWAYADMIN") is NOT a match → Deny fires.
    const parsed = getScp09().body as any;
    const allowed: string[] =
      parsed.Statement[0].Condition.ArnNotEquals["aws:PrincipalArn"];
    const forged = `arn:aws:iam::${WORKLOAD_ACCOUNT_ID}:role/AGENTICAI-d03-nonprod-GATEWAYADMIN`;
    expect(arnNotLikeFires(allowed, forged)).toBe(true);
  });

  it("direct AWS-service principals preserve the business service guard", () => {
    // AgentCore Gateway may be acted on internally by an AWS service
    // principal. Lambda execution-role calls instead use the ordinary role
    // ARN/RoleId controls; they are not direct AWS-service principal calls.
    // The
    // PrincipalIsAWSService=false guard prevents the Deny from firing.
    const parsed = getScp09().body as any;
    const stmt = parsed.Statement[0];
    expect(stmt.Condition.BoolIfExists["aws:PrincipalIsAWSService"]).toBe(
      "false",
    );
    // Defence-in-depth: the action list does not include any wildcard that
    // would sweep in unrelated Bedrock calls.
    const actions: string[] = stmt.Action;
    expect(actions.every((a) => a.startsWith("bedrock-agentcore:"))).toBe(true);
  });

  it("the approved assumed-role context uses its IAM role ARN and live entity ID", () => {
    const parsed = getScp09().body as any;
    const role = authorityFixture({
      governedAccountIds: [WORKLOAD_ACCOUNT_ID],
    }).roles.find((candidate) => candidate.purposes.includes("gateway-admin"))!;
    const context = {
      "aws:PrincipalArn": role.arn,
      "aws:userid": `${role.roleId}:session-abc123`,
      "aws:PrincipalIsAWSService": "false",
    };
    expect(principalGateDenies(parsed.Statement, "bedrock-agentcore:UpdateGateway", context)).toBe(false);
    expect(principalGateDenies(parsed.Statement, "bedrock-agentcore:CreateGateway", context)).toBe(false);
    expect(principalGateDenies(parsed.Statement, "bedrock-agentcore:UpdateGateway", {
      ...context,
      "aws:PrincipalArn": `arn:aws:sts::${WORKLOAD_ACCOUNT_ID}:assumed-role/AgenticAI-D03-nonprod-GatewayAdmin/session-abc123`,
    })).toBe(true);
  });

  it.each(["bedrock-agentcore:CreateGateway", "bedrock-agentcore:UpdateGateway"])(
    "same-name recreation, lookalikes and missing entity context cannot call %s",
    (action) => {
      const parsed = getScp09().body as any;
      const role = authorityFixture({
        governedAccountIds: [WORKLOAD_ACCOUNT_ID],
      }).roles.find((candidate) => candidate.purposes.includes("gateway-admin"))!;
      const approved = {
        "aws:PrincipalArn": role.arn,
        "aws:userid": `${role.roleId}:session`,
        "aws:PrincipalIsAWSService": "false",
      };
      const hostileContexts: Record<string, string>[] = [
        { ...approved, "aws:userid": "AROA99999999999999999:session" },
        { ...approved, "aws:PrincipalArn": `${role.arn}Lookalike` },
        { ...approved, "aws:PrincipalArn": role.arn.replace(WORKLOAD_ACCOUNT_ID, "555555555555") },
        { "aws:PrincipalArn": role.arn, "aws:PrincipalIsAWSService": "false" },
        { "aws:userid": `${role.roleId}:session`, "aws:PrincipalIsAWSService": "false" },
      ];
      for (const hostile of hostileContexts) {
        expect(principalGateDenies(parsed.Statement, action, hostile)).toBe(true);
      }
      expect(parsed.Statement.every((statement: any) =>
        !(statement.Condition.ArnNotEquals && statement.Condition.StringNotLike),
      )).toBe(true);
    },
  );

  it("refuses the original wildcard-only account configuration", () => {
    expect(() => renderSet({
      gatewayAdminWorkloadAccountIds: [WORKLOAD_ACCOUNT_ID],
      protectedAuthorityManifest: undefined,
    })).toThrow(/protectedAuthorityManifest/i);
  });
});

describe("SCP bypass regression — SCP-10 (Tool-invoke allow-list)", () => {
  function getScp10() {
    const set = renderSet({
      platformAccountId: PLATFORM_ACCOUNT_ID,
      gatewayAdminWorkloadAccountIds: [WORKLOAD_ACCOUNT_ID],
      allowedToolTargetArns: ALLOWED_TOOL_TARGET_ARNS,
    });
    const scp10 = set.find((s) => s.id === "scp-10")!;
    expect(scp10).toBeDefined();
    return scp10;
  }

  it("runtime-role invoking a catalogued Lambda is NOT denied (NotResource exempts it)", () => {
    const parsed = getScp10().body as any;
    const stmt = parsed.Statement[0];
    const notResource: string[] = stmt.NotResource;
    const runtimePrincipalPatterns: string[] =
      stmt.Condition.ArnLike["aws:PrincipalArn"];

    const runtimeSession =
      "arn:aws:sts::333333333333:assumed-role/AgenticAI-D03-myapp-runtime/session-1";
    const cataloguedTarget = ALLOWED_TOOL_TARGET_ARNS[0];

    // Principal matches the runtime-role ArnLike condition …
    expect(arnLikeFires(runtimePrincipalPatterns, runtimeSession)).toBe(true);
    // … but the resource IS on the NotResource list, so the Deny does not
    // fire. Simulate this: the Deny applies only when the resource is NOT in
    // the NotResource list.
    const resourceTriggersDeny = !notResource.includes(cataloguedTarget);
    expect(resourceTriggersDeny).toBe(false);
  });

  it("runtime-role invoking a non-catalogued Lambda IS denied", () => {
    const parsed = getScp10().body as any;
    const stmt = parsed.Statement[0];
    const notResource: string[] = stmt.NotResource;
    const runtimePrincipalPatterns: string[] =
      stmt.Condition.ArnLike["aws:PrincipalArn"];

    const runtimeSession =
      "arn:aws:sts::333333333333:assumed-role/AgenticAI-D03-myapp-runtime/session-1";
    const rogueTarget =
      "arn:aws:lambda:us-west-2:333333333333:function:exfiltrate-to-attacker";

    // Principal matches the runtime-role guard …
    expect(arnLikeFires(runtimePrincipalPatterns, runtimeSession)).toBe(true);
    // … and the resource is NOT on the NotResource list → Deny fires.
    const resourceTriggersDeny = !notResource.includes(rogueTarget);
    expect(resourceTriggersDeny).toBe(true);

    // Non-runtime principal (pipeline role) invoking the same rogue target
    // should NOT be self-denied — the ArnLike narrows to runtime roles only.
    const pipelineRole =
      "arn:aws:iam::333333333333:role/AgenticAI-PlatformPipelineRole";
    expect(arnLikeFires(runtimePrincipalPatterns, pipelineRole)).toBe(false);
  });
});
