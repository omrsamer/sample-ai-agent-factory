/**
 * Local denial/control tests for the declared organization authority boundary.
 * The bounded evaluator checks the rendered condition semantics; it does not
 * claim deployed IAM/service-context acceptance.
 */
import { authorityFixture } from "../../../tests/fixtures/protected-authority";
import {
  principalEntityDenyStatements,
  protectedRolesForPurpose,
  renderProtectedAuthorityStatements,
  validateProtectedAuthorityManifest,
  type AuthorityStatement,
  type ProtectedAuthorityManifest,
  type ProtectedAuthorityResource,
} from "./protected-authority";

type MutableManifest = {
  -readonly [K in keyof ProtectedAuthorityManifest]: any;
} & Record<string, any>;
const mutableFixture = (): MutableManifest =>
  structuredClone(
    authorityFixture({
      governedAccountIds: ["333333333333"],
    }),
  ) as MutableManifest;

function matches(pattern: string, value: string): boolean {
  return new RegExp(
    `^${pattern
      .replace(/[.+^${}()|[\]\\]/g, "\\$&")
      .replace(/\*/g, ".*")
      .replace(/\?/g, ".")}$`,
  ).test(value);
}

function denies(
  statements: readonly AuthorityStatement[],
  action: string,
  resource: string,
  context: Readonly<Record<string, string>>,
): boolean {
  const list = (value: unknown): string[] =>
    typeof value === "string" ? [value] : (value as string[]);
  return statements.some((statement) => {
    if (!list(statement.Action).some((pattern) => matches(pattern, action)))
      return false;
    if (!list(statement.Resource).some((pattern) => matches(pattern, resource)))
      return false;
    for (const [operator, entries] of Object.entries(
      (statement.Condition ?? {}) as Record<
        string,
        Record<string, string | string[]>
      >,
    )) {
      for (const [key, expected] of Object.entries(entries)) {
        const actual = context[key];
        const options = list(expected);
        switch (operator) {
          case "ArnNotEquals":
          case "ArnNotEqualsIfExists":
          case "StringNotEqualsIfExists":
            if (actual !== undefined && options.includes(actual)) return false;
            break;
          case "StringNotLike":
            if (
              actual !== undefined &&
              options.some((pattern) => matches(pattern, actual))
            )
              return false;
            break;
          case "ArnLike":
            if (
              actual === undefined ||
              !options.some((pattern) => matches(pattern, actual))
            )
              return false;
            break;
          case "BoolIfExists":
            if (actual !== undefined && !options.includes(actual)) return false;
            break;
          default:
            throw new Error(`Unsupported test evaluator operator: ${operator}`);
        }
      }
    }
    return true;
  });
}

describe("ProtectedAuthorityManifest admission", () => {
  it("accepts the complete synthetic reviewed graph and keeps exact entity bindings", () => {
    const fixture = authorityFixture();
    expect(validateProtectedAuthorityManifest(fixture)).toBe(fixture);
    expect(protectedRolesForPurpose(fixture, "gateway-admin")).toHaveLength(3);
    expect(protectedRolesForPurpose(fixture, "guardrail-admin")).toHaveLength(
      1,
    );
  });

  const mutations: [string, (manifest: MutableManifest) => void][] = [
    [
      "invoker on a deployment input",
      (m) => {
        m.resources.find((r: any) => r.kind === "s3-object").invokerIds = [
          "central-owner",
        ];
      },
    ],
    [
      "unregistered Gateway invoker",
      (m) => {
        m.resources.find((r: any) => r.kind === "gateway").invokerIds = [
          "unknown-caller",
        ];
      },
    ],
    [
      "empty explicit invocation approval",
      (m) => {
        m.resources.find((r: any) => r.kind === "gateway").invokerIds = [];
      },
    ],
    [
      "qualified Lambda consumer record",
      (m) => {
        m.resources.find((r: any) => r.kind === "lambda").arn +=
          ":approved-alias";
      },
    ],
    [
      "role and resource record ID collision",
      (m) => {
        m.resources[0].id = m.roles[0].id;
      },
    ],
    [
      "unknown proof boolean",
      (m) => {
        m.protectionAttached = true;
      },
    ],
    [
      "role name wildcard",
      (m) => {
        m.roles[2].arn += "*";
      },
    ],
    [
      "account wildcard",
      (m) => {
        m.roles[2].arn = m.roles[2].arn.replace("333333333333", "*");
      },
    ],
    [
      "STS session as identity",
      (m) => {
        m.roles[2].arn = "arn:aws:sts::333333333333:assumed-role/admin/session";
      },
    ],
    [
      "service-linked authority root",
      (m) => {
        m.roles[0].arn =
          "arn:aws:iam::111111111111:role/aws-service-role/cloudformation.amazonaws.com/AWSServiceRoleForCloudFormationStackSetsOrgAdmin";
      },
    ],
    [
      "missing live role entity",
      (m) => {
        delete m.roles[2].roleId;
      },
    ],
    [
      "duplicate live role entity",
      (m) => {
        m.roles[2].roleId = m.roles[1].roleId;
      },
    ],
    [
      "unapproved role account",
      (m) => {
        m.roles[2].arn = m.roles[2].arn.replace("333333333333", "888888888888");
      },
    ],
    [
      "governed central root",
      (m) => {
        m.governedAccountIds.push("111111111111");
      },
    ],
    [
      "governed management authority",
      (m) => {
        m.governedAccountIds.push(m.managementAccountId);
      },
    ],
    [
      "no central root",
      (m) => {
        m.roles[2].lifecycleControllerIds = [];
      },
    ],
    [
      "self lifecycle control",
      (m) => {
        m.roles[2].lifecycleControllerIds = [m.roles[2].id];
      },
    ],
    [
      "controller graph cycle",
      (m) => {
        m.roles[1].lifecycleControllerIds = [m.roles[2].id];
        m.roles[2].lifecycleControllerIds = [m.roles[1].id];
      },
    ],
    [
      "unknown lifecycle controller",
      (m) => {
        m.roles[2].lifecycleControllerIds = ["missing"];
      },
    ],
    [
      "unknown PassRole controller",
      (m) => {
        m.roles[2].passRoleControllerIds = ["missing"];
      },
    ],
    [
      "unprotected attached policy",
      (m) => {
        m.roles[2].policyResourceIds = [];
      },
    ],
    [
      "unprotected boundary policy",
      (m) => {
        m.roles[2].permissionsBoundaryArn =
          "arn:aws:iam::333333333333:policy/unprotected";
      },
    ],
    [
      "invalid trust digest",
      (m) => {
        m.roles[2].trustPolicySha256 = "approved";
      },
    ],
    [
      "invalid inline policy digest",
      (m) => {
        m.roles[2].inlinePolicySha256 = { Admin: "approved" };
      },
    ],
    [
      "missing consumer inventory",
      (m) => {
        m.roles[2].consumerResourceIds = [];
      },
    ],
    [
      "missing Lambda consumer",
      (m) => {
        m.roles[2].consumerResourceIds = [
          m.resources.find((r: any) => r.kind === "gateway").id,
        ];
      },
    ],
    [
      "wrong consumer execution role",
      (m) => {
        m.resources.find(
          (r: any) => r.id === m.roles[2].consumerResourceIds[0],
        ).executionRoleArn = m.roles[1].arn;
      },
    ],
    [
      "missing owner stack",
      (m) => {
        m.resources.find(
          (r: any) =>
            r.kind === "lambda" && r.executionRoleArn === m.roles[2].arn,
        ).dependsOnIds = [
          m.resources.find((r: any) => r.kind === "s3-object").id,
        ];
      },
    ],
    [
      "missing executable input",
      (m) => {
        for (const r of m.resources)
          r.dependsOnIds = r.dependsOnIds.filter(
            (id: string) =>
              id !== m.resources.find((x: any) => x.kind === "s3-object").id,
          );
      },
    ],
    [
      "unprotected Mantle interceptor",
      (m) => {
        const gateway = m.resources.find((r: any) => r.kind === "gateway");
        gateway.dependsOnIds = gateway.dependsOnIds.filter(
          (id: string) =>
            m.resources.find((r: any) => r.id === id).kind !== "lambda",
        );
      },
    ],
    [
      "unknown resource dependency",
      (m) => {
        m.resources[0].dependsOnIds = ["missing"];
      },
    ],
    [
      "resource graph cycle",
      (m) => {
        m.resources[0].dependsOnIds = [m.resources[1].id];
        m.resources[1].dependsOnIds = [m.resources[0].id];
      },
    ],
    [
      "unknown resource controller",
      (m) => {
        m.resources[0].controllerIds = ["missing"];
      },
    ],
    [
      "empty resource controllers",
      (m) => {
        m.resources[0].controllerIds = [];
      },
    ],
    [
      "wildcard resource ARN",
      (m) => {
        m.resources[0].arn += "*";
      },
    ],
    [
      "unbound S3 ownership",
      (m) => {
        delete m.resources.find((r: any) => r.kind === "s3-object").accountId;
      },
    ],
    [
      "stale policy digest missing",
      (m) => {
        delete m.resources.find((r: any) => r.kind === "policy").documentSha256;
      },
    ],
    [
      "live policy entity missing",
      (m) => {
        delete m.resources.find((r: any) => r.kind === "policy").policyId;
      },
    ],
    [
      "default policy version missing",
      (m) => {
        delete m.resources.find((r: any) => r.kind === "policy")
          .defaultVersionId;
      },
    ],
    [
      "Lambda code binding missing",
      (m) => {
        delete m.resources.find((r: any) => r.kind === "lambda").codeSha256;
      },
    ],
    [
      "stack template binding missing",
      (m) => {
        delete m.resources.find((r: any) => r.kind === "stack").documentSha256;
      },
    ],
    [
      "resource configuration binding missing",
      (m) => {
        delete m.resources.find((r: any) => r.kind === "gateway")
          .configurationSha256;
      },
    ],
    [
      "orphan privileged resource",
      (m) => {
        m.roles[1].consumerResourceIds =
          m.roles[1].consumerResourceIds.slice(1);
      },
    ],
  ];
  it.each(mutations)(
    "rejects %s before rendering exceptions",
    (_label, mutate) => {
      const fixture = mutableFixture();
      mutate(fixture);
      expect(() => validateProtectedAuthorityManifest(fixture)).toThrow(
        /ProtectedAuthorityManifest/,
      );
    },
  );
});

describe("entity-binding condition semantics", () => {
  const role = authorityFixture({ governedAccountIds: ["333333333333"] })
    .roles[2];
  const statements = principalEntityDenyStatements(
    "Business",
    ["service:Mutate"],
    "*",
    [role],
  );
  const correct = {
    "aws:PrincipalArn": role.arn,
    "aws:userid": `${role.roleId}:approved-session`,
  };

  it("preserves the approved exact assumed-role entity", () => {
    expect(denies(statements, "service:Mutate", "*", correct)).toBe(false);
  });
  it.each([
    [
      "recreated same-name role",
      { ...correct, "aws:userid": "AROA99999999999999999:session" },
    ],
    [
      "prefix lookalike",
      { ...correct, "aws:PrincipalArn": `${role.arn}Lookalike` },
    ],
    [
      "other account",
      {
        ...correct,
        "aws:PrincipalArn": role.arn.replace("333333333333", "444444444444"),
      },
    ],
    [
      "STS-session ARN misconception",
      {
        ...correct,
        "aws:PrincipalArn":
          "arn:aws:sts::333333333333:assumed-role/admin/session",
      },
    ],
    ["missing entity context", { "aws:PrincipalArn": role.arn }],
    ["missing ARN context", { "aws:userid": `${role.roleId}:session` }],
    ["no identity context", {}],
  ])("denies %s independently", (_label, context) => {
    expect(denies(statements, "service:Mutate", "*", context)).toBe(true);
  });
  it("never puts both negative identity conditions in one AND statement", () => {
    expect(statements).toHaveLength(2);
    for (const statement of statements) {
      const condition = statement.Condition as Record<string, unknown>;
      expect(Object.keys(condition)).toHaveLength(1);
    }
  });
  it("has no exemption when no reviewed identities exist", () => {
    expect(
      denies(
        principalEntityDenyStatements("Missing", ["service:Mutate"], "*", []),
        "service:Mutate",
        "*",
        correct,
      ),
    ).toBe(true);
  });
  it("does not propagate an AWS-service exception into authority protections", () => {
    expect(
      denies(statements, "service:Mutate", "*", {
        "aws:PrincipalIsAWSService": "true",
      }),
    ).toBe(true);
    const business = principalEntityDenyStatements(
      "Business",
      ["service:Mutate"],
      "*",
      [role],
      { awsServiceExempt: true },
    );
    expect(
      denies(business, "service:Mutate", "*", {
        "aws:PrincipalIsAWSService": "true",
      }),
    ).toBe(false);
  });
});

describe("approved Gateway callers", () => {
  const fixture = mutableFixture();
  const caller = {
    ...fixture.roles[0],
    id: "approved-application",
    arn: "arn:aws:iam::333333333333:role/ApprovedApplication",
    roleId: "AROA77777777777777777",
    purposes: ["gateway-invoker"],
    lifecycleControllerIds: ["central-owner"],
  };
  fixture.roles.push(caller);
  const gateway = fixture.resources.find((r: any) => r.kind === "gateway");
  const interceptor = fixture.resources.find(
    (r: any) => r.kind === "lambda" && r.id.endsWith("-interceptor"),
  );
  const mantle = fixture.roles.find((r: any) => r.purposes.includes("mantle"));
  gateway.invokerIds = [caller.id];
  interceptor.invokerIds = [mantle.id];
  const statements = renderProtectedAuthorityStatements(fixture);
  const identity = (role: typeof caller) => ({
    "aws:PrincipalArn": role.arn,
    "aws:userid": `${role.roleId}:approved`,
  });

  it("preserves the reviewed application caller without allowing configuration changes", () => {
    expect(
      denies(
        statements,
        "bedrock-agentcore:InvokeGateway",
        gateway.arn,
        identity(caller),
      ),
    ).toBe(false);
    expect(
      denies(
        statements,
        "bedrock-agentcore:UpdateGateway",
        gateway.arn,
        identity(caller),
      ),
    ).toBe(true);
    expect(
      denies(
        statements,
        "iam:PassRole",
        caller.arn,
        identity(fixture.roles[0]),
      ),
    ).toBe(true);
  });
  it.each([
    [
      "recreated approved caller",
      { ...identity(caller), "aws:userid": "AROA88888888888888888:session" },
    ],
    [
      "caller name lookalike",
      { ...identity(caller), "aws:PrincipalArn": `${caller.arn}Extra` },
    ],
    [
      "ordinary IAM-authorized caller",
      {
        "aws:PrincipalArn": "arn:aws:iam::333333333333:role/MemberAdmin",
        "aws:userid": "AROA88888888888888888:session",
      },
    ],
    ["missing IAM principal context", {}],
  ])("denies %s at the Gateway", (_label, context) => {
    expect(
      denies(
        statements,
        "bedrock-agentcore:InvokeGateway",
        gateway.arn,
        context,
      ),
    ).toBe(true);
  });
  it("preserves the exact Gateway role invoking its reviewed interceptor while denying code changes", () => {
    expect(
      denies(
        statements,
        "lambda:InvokeFunction",
        `${interceptor.arn}:approved`,
        identity(mantle),
      ),
    ).toBe(false);
    expect(
      denies(
        statements,
        "lambda:UpdateFunctionCode",
        interceptor.arn,
        identity(mantle),
      ),
    ).toBe(true);
    expect(
      denies(
        statements,
        "lambda:InvokeFunction",
        interceptor.arn,
        identity(caller),
      ),
    ).toBe(true);
  });
  it("defaults undeclared Gateway callers to exact controllers", () => {
    const original = authorityFixture({ governedAccountIds: ["333333333333"] });
    const originalGateway = original.resources.find(
      (r) => r.kind === "gateway",
    )!;
    const executor = original.roles.find(
      (r) => r.id === originalGateway.controllerIds[0],
    )!;
    expect(
      denies(
        renderProtectedAuthorityStatements(original),
        "bedrock-agentcore:InvokeGateway",
        originalGateway.arn,
        identity(executor),
      ),
    ).toBe(false);
    expect(
      denies(
        renderProtectedAuthorityStatements(original),
        "bedrock-agentcore:InvokeGateway",
        originalGateway.arn,
        identity(caller),
      ),
    ).toBe(true);
  });
});

describe("protected role, consumers and input enforcement", () => {
  const manifest = authorityFixture({ governedAccountIds: ["333333333333"] });
  const statements = renderProtectedAuthorityStatements(manifest);
  const central = manifest.roles[0];
  const executor = manifest.roles[1];
  const gatewayAdmin = manifest.roles[2];
  const provider = manifest.resources.find(
    (r) => r.kind === "lambda" && r.executionRoleArn === gatewayAdmin.arn,
  )!;
  const stack = manifest.resources.find((r) => r.kind === "stack")!;
  const asset = manifest.resources.find((r) => r.kind === "s3-object")!;
  const policy = manifest.resources.find((r) => r.kind === "policy")!;
  const identity = (role: typeof central) => ({
    "aws:PrincipalArn": role.arn,
    "aws:userid": `${role.roleId}:session`,
  });
  const attacker = {
    "aws:PrincipalArn": "arn:aws:iam::333333333333:role/MemberAdmin",
    "aws:userid": "AROA88888888888888888:admin",
  };

  it.each([
    "iam:CreateRole",
    "iam:DeleteRole",
    "iam:UpdateAssumeRolePolicy",
    "iam:PutRolePolicy",
    "iam:AttachRolePolicy",
    "iam:DeleteRolePermissionsBoundary",
    "iam:TagRole",
  ])(
    "denies %s on privileged role while preserving central lifecycle authority",
    (action) => {
      expect(denies(statements, action, gatewayAdmin.arn, attacker)).toBe(true);
      expect(
        denies(statements, action, gatewayAdmin.arn, identity(central)),
      ).toBe(false);
      expect(
        denies(statements, action, gatewayAdmin.arn, identity(executor)),
      ).toBe(true);
    },
  );
  it.each([
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:DeletePolicy",
  ])("fences policy mutation %s", (action) => {
    expect(denies(statements, action, policy.arn, attacker)).toBe(true);
    expect(denies(statements, action, policy.arn, identity(central))).toBe(
      false,
    );
  });
  it.each([
    "lambda:UpdateFunctionCode",
    "lambda:UpdateFunctionConfiguration",
    "lambda:InvokeFunction",
    "lambda:InvokeFunctionUrl",
    "lambda:AddPermission",
    "lambda:CreateFunctionUrlConfig",
  ])("fences privileged consumer %s including aliases", (action) => {
    expect(denies(statements, action, provider.arn, attacker)).toBe(true);
    expect(denies(statements, action, `${provider.arn}:live`, attacker)).toBe(
      true,
    );
    expect(denies(statements, action, provider.arn, identity(executor))).toBe(
      false,
    );
  });
  it.each([
    "cloudformation:UpdateStack",
    "cloudformation:CreateChangeSet",
    "cloudformation:ExecuteChangeSet",
    "cloudformation:ContinueUpdateRollback",
    "cloudformation:DeleteStack",
  ])(
    "fences stored execution-role reuse through %s without a new PassRole request",
    (action) => {
      expect(denies(statements, action, stack.arn, attacker)).toBe(true);
      expect(denies(statements, action, stack.arn, identity(executor))).toBe(
        false,
      );
    },
  );
  it("fences executable asset substitution with a legitimate publisher control", () => {
    expect(denies(statements, "s3:PutObject", asset.arn, attacker)).toBe(true);
    expect(
      denies(statements, "s3:PutObject", asset.arn, identity(central)),
    ).toBe(false);
  });
  it("protects bucket policy and new artifact keys before they become individual inputs", () => {
    const bucket = manifest.resources.find((r) => r.kind === "s3-bucket")!;
    const newAsset = `${bucket.arn}/assets/new-content-addressed-build.zip`;
    expect(denies(statements, "s3:PutBucketPolicy", bucket.arn, attacker)).toBe(
      true,
    );
    expect(
      denies(statements, "s3:PutBucketPolicy", bucket.arn, identity(central)),
    ).toBe(false);
    expect(denies(statements, "s3:PutObject", newAsset, attacker)).toBe(true);
    expect(
      denies(statements, "s3:PutObject", newAsset, identity(central)),
    ).toBe(false);
  });
  it("fences event-source attachment to both unqualified and qualified function targets", () => {
    for (const target of [provider.arn, `${provider.arn}:live`]) {
      expect(
        denies(statements, "lambda:CreateEventSourceMapping", "*", {
          ...attacker,
          "lambda:FunctionArn": target,
        }),
      ).toBe(true);
      expect(
        denies(statements, "lambda:CreateEventSourceMapping", "*", {
          ...identity(executor),
          "lambda:FunctionArn": target,
        }),
      ).toBe(false);
    }
  });
  it("allows PassRole only from the exact controller to the reviewed service and consumer", () => {
    const approved = {
      ...identity(executor),
      "iam:PassedToService": "lambda.amazonaws.com",
      "iam:AssociatedResourceArn": provider.arn,
    };
    expect(denies(statements, "iam:PassRole", gatewayAdmin.arn, approved)).toBe(
      false,
    );
    expect(
      denies(statements, "iam:PassRole", gatewayAdmin.arn, {
        ...approved,
        ...attacker,
      }),
    ).toBe(true);
    expect(
      denies(statements, "iam:PassRole", gatewayAdmin.arn, {
        ...approved,
        "iam:PassedToService": "ec2.amazonaws.com",
      }),
    ).toBe(true);
    expect(
      denies(statements, "iam:PassRole", gatewayAdmin.arn, {
        ...approved,
        "iam:AssociatedResourceArn": `${provider.arn}-attacker`,
      }),
    ).toBe(true);
  });
  it("fails closed when a service omits PassRole service or associated-resource context", () => {
    expect(
      denies(statements, "iam:PassRole", gatewayAdmin.arn, identity(executor)),
    ).toBe(true);
    expect(
      denies(statements, "iam:PassRole", gatewayAdmin.arn, {
        ...identity(executor),
        "iam:PassedToService": "lambda.amazonaws.com",
      }),
    ).toBe(true);
  });
  it("preserves unrelated resources and reads of protected resources", () => {
    expect(
      denies(
        statements,
        "lambda:UpdateFunctionCode",
        `${provider.arn}-unrelated`,
        attacker,
      ),
    ).toBe(false);
    expect(
      denies(
        statements,
        "cloudformation:UpdateStack",
        stack.arn.replace("ProtectedAuthorityFixture", "OrdinaryStack"),
        attacker,
      ),
    ).toBe(false);
    expect(
      denies(statements, "lambda:GetFunction", provider.arn, attacker),
    ).toBe(false);
    expect(denies(statements, "iam:GetRole", gatewayAdmin.arn, attacker)).toBe(
      false,
    );
  });
  it("fences StackSet creation and service-managed operation entry points centrally", () => {
    expect(
      denies(statements, "cloudformation:CreateStackSet", "*", attacker),
    ).toBe(true);
    expect(
      denies(
        statements,
        "cloudformation:CreateStackSet",
        "*",
        identity(central),
      ),
    ).toBe(false);
    expect(
      denies(
        statements,
        "cloudformation:CreateStackSet",
        "*",
        identity(executor),
      ),
    ).toBe(true);
  });
  it("renders only one governed cell's guards when directly attaching to that account", () => {
    const all = authorityFixture();
    const one = renderProtectedAuthorityStatements(all, "333333333333");
    const rendered = JSON.stringify(one);
    expect(rendered).toContain("333333333333");
    expect(rendered).not.toContain("222222222222");
    expect(rendered).not.toContain("444444444444");
    expect(() =>
      renderProtectedAuthorityStatements(all, "888888888888"),
    ).toThrow(/exact governed/);
  });
  it("renders the same policy when reviewed role/resource record order changes", () => {
    const reordered = {
      ...manifest,
      roles: [...manifest.roles].reverse(),
      resources: [...manifest.resources].reverse(),
    };
    expect(renderProtectedAuthorityStatements(reordered)).toEqual(statements);
  });
});

describe("additional controller and mutable-input boundaries", () => {
  it("blocks protected interactive and batch builds and fences project resource grants", () => {
    const manifest = mutableFixture();
    const executor = manifest.roles[1];
    const project =
      "arn:aws:codebuild:us-west-2:333333333333:project/protected-build";
    manifest.resources.push({
      id: "reviewed-build",
      kind: "build",
      arn: project,
      executionRoleArn: executor.arn,
      controllerIds: [executor.id],
      dependsOnIds: [
        manifest.resources.find((r: any) => r.kind === "s3-object").id,
      ],
      configurationSha256: "c".repeat(64),
    });
    executor.consumerResourceIds.push("reviewed-build");
    const statements = renderProtectedAuthorityStatements(
      manifest as ProtectedAuthorityManifest,
    );
    const approved = {
      "aws:PrincipalArn": executor.arn,
      "aws:userid": `${executor.roleId}:session`,
    };
    const ordinary = {
      "aws:PrincipalArn": "arn:aws:iam::333333333333:role/ordinary-admin",
      "aws:userid": "AROA12345678901234567:session",
    };
    for (const action of [
      "codebuild:StartSandbox",
      "codebuild:StartBuildBatch",
      "codebuild:RetryBuildBatch",
    ]) {
      expect(denies(statements, action, project, ordinary)).toBe(true);
      expect(denies(statements, action, project, approved)).toBe(true);
      expect(
        denies(
          statements,
          action,
          project.replace("protected-build", "ordinary-build"),
          ordinary,
        ),
      ).toBe(false);
    }
    for (const action of [
      "codebuild:PutResourcePolicy",
      "codebuild:DeleteResourcePolicy",
      "codebuild:UpdateProjectVisibility",
      "codebuild:StartBuild",
    ]) {
      expect(denies(statements, action, project, ordinary)).toBe(true);
      expect(denies(statements, action, project, approved)).toBe(false);
    }
  });
  it("fences saved and distributed-map execution redrives while preserving the enrolled controller", () => {
    const manifest = mutableFixture();
    const executor = manifest.roles[1];
    const base =
      "arn:aws:states:us-west-2:333333333333:stateMachine:protected-controller";
    manifest.resources.push({
      id: "saved-state-machine",
      kind: "state-machine",
      arn: base,
      executionRoleArn: executor.arn,
      controllerIds: [executor.id],
      dependsOnIds: [
        manifest.resources.find((r: any) => r.kind === "s3-object").id,
      ],
      configurationSha256: "c".repeat(64),
    });
    executor.consumerResourceIds.push("saved-state-machine");
    const statements = renderProtectedAuthorityStatements(
      manifest as ProtectedAuthorityManifest,
    );
    const executionBase = base.replace(":stateMachine:", ":execution:");
    for (const execution of [
      `${executionBase}:saved-run`,
      `${executionBase}/map-label:saved-child`,
    ]) {
      expect(
        denies(statements, "states:RedriveExecution", execution, {
          "aws:PrincipalArn": "arn:aws:iam::333333333333:role/ordinary-admin",
          "aws:userid": "AROA12345678901234567:session",
        }),
      ).toBe(true);
      expect(
        denies(statements, "states:RedriveExecution", execution, {
          "aws:PrincipalArn": executor.arn,
          "aws:userid": `${executor.roleId}:session`,
        }),
      ).toBe(false);
    }
    expect(
      denies(
        statements,
        "states:RedriveExecution",
        "arn:aws:states:us-west-2:333333333333:execution:ordinary-controller:run",
        {
          "aws:PrincipalArn": "arn:aws:iam::333333333333:role/ordinary-admin",
          "aws:userid": "AROA12345678901234567:session",
        },
      ),
    ).toBe(false);
  });
  const examples: {
    kind: ProtectedAuthorityResource["kind"];
    arn: string;
    action: string;
    consumesRole?: boolean;
    document?: boolean;
  }[] = [
    {
      kind: "pipeline",
      arn: "arn:aws:codepipeline:us-west-2:333333333333:protected-pipeline",
      action: "codepipeline:StartPipelineExecution",
      consumesRole: true,
    },
    {
      kind: "build",
      arn: "arn:aws:codebuild:us-west-2:333333333333:project/protected-build",
      action: "codebuild:StartBuild",
      consumesRole: true,
    },
    {
      kind: "ecr",
      arn: "arn:aws:ecr:us-west-2:333333333333:repository/protected-images",
      action: "ecr:PutImage",
    },
    {
      kind: "kms",
      arn: "arn:aws:kms:us-west-2:333333333333:key/11111111-2222-4333-8444-555555555555",
      action: "kms:PutKeyPolicy",
      document: true,
    },
    {
      kind: "ssm",
      arn: "arn:aws:ssm:us-west-2:333333333333:parameter/protected/config",
      action: "ssm:PutParameter",
    },
    {
      kind: "secret",
      arn: "arn:aws:secretsmanager:us-west-2:333333333333:secret:protected/config-abcdef",
      action: "secretsmanager:PutSecretValue",
    },
    {
      kind: "connection",
      arn: "arn:aws:codeconnections:us-west-2:333333333333:connection/11111111-2222-4333-8444-555555555555",
      action: "codeconnections:DeleteConnection",
    },
    {
      kind: "layer",
      arn: "arn:aws:lambda:us-west-2:333333333333:layer:protected-layer:1",
      action: "lambda:AddLayerVersionPermission",
    },
    {
      kind: "state-machine",
      arn: "arn:aws:states:us-west-2:333333333333:stateMachine:protected-controller",
      action: "states:StartExecution",
      consumesRole: true,
    },
    {
      kind: "lambda-event-source-mapping",
      arn: "arn:aws:lambda:us-west-2:333333333333:event-source-mapping:11111111-2222-4333-8444-555555555555",
      action: "lambda:DeleteEventSourceMapping",
    },
    {
      kind: "stack-set",
      arn: "arn:aws:cloudformation:us-west-2:333333333333:stackset/ProtectedStackSet:11111111-2222-4333-8444-555555555555",
      action: "cloudformation:UpdateStackSet",
    },
  ];
  it.each(examples)(
    "fences $kind mutation/execution with a positive approved-controller twin",
    (example) => {
      const manifest = mutableFixture();
      const executor = manifest.roles[1];
      const isStackSet = example.kind === "stack-set";
      const controller = isStackSet ? manifest.roles[0] : executor;
      manifest.resources.push({
        id: "additional-resource",
        kind: example.kind,
        arn: example.arn,
        controllerIds: [controller.id],
        dependsOnIds: [
          manifest.resources.find((r: any) => r.kind === "s3-object").id,
        ],
        configurationSha256: "c".repeat(64),
        ...(example.document ? { documentSha256: "d".repeat(64) } : {}),
        ...(example.consumesRole ? { executionRoleArn: executor.arn } : {}),
      });
      if (example.consumesRole)
        executor.consumerResourceIds.push("additional-resource");
      const statements = renderProtectedAuthorityStatements(
        manifest as ProtectedAuthorityManifest,
      );
      const attacker = {
        "aws:PrincipalArn": "arn:aws:iam::333333333333:role/MemberAdmin",
        "aws:userid": "AROA88888888888888888:admin",
      };
      const approved = {
        "aws:PrincipalArn": controller.arn,
        "aws:userid": `${controller.roleId}:approved`,
      };
      expect(denies(statements, example.action, example.arn, attacker)).toBe(
        true,
      );
      expect(denies(statements, example.action, example.arn, approved)).toBe(
        false,
      );
    },
  );
});
