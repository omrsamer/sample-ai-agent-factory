/**
 * Phase 27 conformance — Agent Factory Portal (read-only milestone).
 *
 * Pins the contract that lets the portal exist without weakening the
 * operating model:
 *   - opt-in: three dedicated stages, nothing else references the portal;
 *   - "central visibility must not become central write access": the API role
 *     and the cell fleet reader role hold read actions only;
 *   - the fleet reader role trusts exactly the portal API role, with an
 *     external id;
 *   - every data route sits behind the JWT authorizer and only GET exists;
 *   - hosting is private S3 behind CloudFront with the edge web ACL;
 *   - cdk-nag AwsSolutions and NIST 800-53 R5 report no unsuppressed error.
 *
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: MIT-0
 */
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { App, Aspects, Stack } from "aws-cdk-lib";
import { Annotations, Match, Template } from "aws-cdk-lib/assertions";
import { AwsSolutionsChecks, NIST80053R5Checks } from "cdk-nag";

import {
  PORTAL_API_GUARDRAIL_ACTIONS,
  PORTAL_API_PIPELINE_ACTIONS,
  PORTAL_API_REGISTRY_ACTIONS,
  PORTAL_COGNITO_GROUPS,
  PORTAL_FLEET_READER_AGENTCORE_ACTIONS,
  PORTAL_FLEET_READER_CLOUDWATCH_ACTIONS,
  PORTAL_FLEET_READER_LOGS_QUERY_ACTIONS,
  PORTAL_FLEET_READER_LOGS_RESULT_ACTIONS,
  assertPortalReadOnlyAction,
} from "@agenticai/agent-factory-portal";
import {
  AgentFactoryPortalEdgeStack,
  AgentFactoryPortalStack,
} from "../../apps/platform-account/lib/agent-factory-portal-stack";
import {
  AGENT_FACTORY_PORTAL_STAGES,
  addAgentFactoryPortalStage,
} from "../../apps/platform-account/lib/agent-factory-portal-stages";
import { AgentFactoryPortalFleetReaderStack } from "../../apps/workload-account/lib/agent-factory-portal-fleet-reader-stack";

const PLATFORM = "222222222222";
const CELL = "444444444444";
const REGION = "eu-west-1";
const WEB_ACL = `arn:aws:wafv2:us-east-1:${PLATFORM}:global/webacl/portal/11111111-2222-4333-8444-555555555555`;
const EXTERNAL_ID = "portal-fleet-reader-0123456789";
const ENTRA = {
  tenantId: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
  spaClientId: "11111111-2222-4333-8444-555555555555",
  apiAudience: "api://agent-factory-portal",
  apiScope: "api://agent-factory-portal/access_as_user",
  groupRoleMap: { "Portal.Platform": "platform" as const, "Portal.Reader": "readonly" as const },
};

// Created at module load: the describe blocks synthesize stacks immediately.
const assets = fs.mkdtempSync(path.join(os.tmpdir(), "portal-conformance-"));
const apiCode = path.join(assets, "api");
const webDist = path.join(assets, "web");
fs.mkdirSync(apiCode);
fs.mkdirSync(webDist);
fs.writeFileSync(path.join(apiCode, "handler.py"), "def handler(event, context):\n    return {}\n");
fs.writeFileSync(path.join(webDist, "index.html"), "<!doctype html><title>portal</title>\n");

afterAll(() => {
  fs.rmSync(assets, { recursive: true, force: true });
});

function withNag(app: App): void {
  Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true }));
  Aspects.of(app).add(new NIST80053R5Checks({ verbose: true }));
}

function nagErrors(stack: Stack): string[] {
  return Annotations.fromStack(stack)
    .findError("*", Match.stringLikeRegexp("(AwsSolutions|NIST\\.800\\.53\\.R5)-.*"))
    .map((entry) => `${entry.id}: ${String(entry.entry.data).split("\n")[0]}`);
}

function portalStack(identityProvider: "cognito" | "entra" = "cognito"): AgentFactoryPortalStack {
  const app = new App();
  withNag(app);
  return new AgentFactoryPortalStack(app, "Portal", {
    env: { account: PLATFORM, region: REGION },
    environment: "nonprod",
    identityProvider,
    entra: identityProvider === "entra" ? ENTRA : undefined,
    webAclArn: WEB_ACL,
    cells: [
      {
        tenantId: "shared",
        agentId: "shared",
        environment: "nonprod",
        accountId: CELL,
        region: REGION,
        externalId: EXTERNAL_ID,
        alarmNamePrefix: "agenticai-shared-shared-nonprod",
        pipelineName: "agenticai-workload-shared-shared",
      },
    ],
    apiCodePath: apiCode,
    webDistPath: webDist,
  });
}

function readerStack(): AgentFactoryPortalFleetReaderStack {
  const app = new App();
  withNag(app);
  return new AgentFactoryPortalFleetReaderStack(app, "Reader", {
    env: { account: CELL, region: REGION },
    environment: "nonprod",
    platformAccountId: PLATFORM,
    externalId: EXTERNAL_ID,
  });
}

function edgeStack(cidrs: readonly string[] = ["198.51.100.0/24"]): AgentFactoryPortalEdgeStack {
  const app = new App();
  withNag(app);
  return new AgentFactoryPortalEdgeStack(app, "Edge", {
    env: { account: PLATFORM, region: "us-east-1" },
    environment: "nonprod",
    allowedIpv4Cidrs: cidrs,
  });
}

type Statement = { Action: string | string[]; Resource: unknown; Effect: string; Sid?: string };

function statementsOf(template: Template): Statement[] {
  const policies = template.findResources("AWS::IAM::ManagedPolicy");
  return Object.values(policies).flatMap(
    (p) => (p as { Properties: { PolicyDocument: { Statement: Statement[] } } }).Properties.PolicyDocument.Statement,
  );
}

function actionsOf(statements: Statement[]): string[] {
  return statements.flatMap((s) => (Array.isArray(s.Action) ? s.Action : [s.Action]));
}

describe("Phase 27 — fleet reader role (Workstream cell)", () => {
  const stack = readerStack();
  const template = Template.fromStack(stack);

  it("holds read-only actions and nothing else", () => {
    const actions = actionsOf(statementsOf(template));
    const expected = [
      ...PORTAL_FLEET_READER_AGENTCORE_ACTIONS,
      ...PORTAL_FLEET_READER_CLOUDWATCH_ACTIONS,
      ...PORTAL_FLEET_READER_LOGS_QUERY_ACTIONS,
      ...PORTAL_FLEET_READER_LOGS_RESULT_ACTIONS,
    ];
    expect([...actions].sort()).toEqual([...expected].sort());
    for (const action of actions) expect(() => assertPortalReadOnlyAction(action)).not.toThrow();
  });

  it("rejects a mutating action at synthesis", () => {
    for (const action of [
      "bedrock-agentcore:UpdateGateway",
      "bedrock-agentcore:CreatePolicy",
      "bedrock-agentcore:InvokeAgentRuntime",
      "logs:DeleteLogGroup",
      "cloudwatch:PutMetricAlarm",
    ]) {
      expect(() => assertPortalReadOnlyAction(action)).toThrow(/not a read-only operation/);
    }
  });

  it("trusts only the portal API role of the Platform account, with the external id", () => {
    template.hasResourceProperties("AWS::IAM::Role", {
      RoleName: "AgenticAI-PortalFleetReader-nonprod",
      AssumeRolePolicyDocument: {
        Statement: [
          Match.objectLike({
            Action: "sts:AssumeRole",
            Effect: "Allow",
            Condition: {
              ArnEquals: {
                "aws:PrincipalArn": {
                  "Fn::Join": ["", Match.arrayWith([`:iam::${PLATFORM}:role/AgenticAI-PortalApi-nonprod`])],
                },
              },
              StringEquals: { "sts:ExternalId": EXTERNAL_ID },
            },
          }),
        ],
      },
    });
  });

  it("scopes AgentCore reads to the cell account and Region", () => {
    const agentcore = statementsOf(template).find((s) => s.Sid === "PortalReadAgentCore")!;
    expect(JSON.stringify(agentcore.Resource)).toContain(`:bedrock-agentcore:${REGION}:${CELL}:runtime/*`);
    expect(JSON.stringify(agentcore.Resource)).not.toContain('"*"');
  });

  it("requires a real external id and account", () => {
    const app = new App();
    expect(
      () =>
        new AgentFactoryPortalFleetReaderStack(app, "Bad", {
          env: { account: CELL, region: REGION },
          environment: "nonprod",
          platformAccountId: PLATFORM,
          externalId: "short",
        }),
    ).toThrow(/externalId/);
  });

  it("passes cdk-nag", () => {
    expect(nagErrors(stack)).toEqual([]);
  });
});

describe("Phase 27 — portal stack (Platform account)", () => {
  const stack = portalStack();
  const template = Template.fromStack(stack);

  it("API role holds read actions, its own telemetry writes, and AssumeRole on the cell reader only", () => {
    const role = template.findResources("AWS::IAM::Role", {
      Properties: { RoleName: "AgenticAI-PortalApi-nonprod" },
    });
    expect(Object.keys(role)).toHaveLength(1);
    const roleId = Object.keys(role)[0];
    const policies = template.findResources("AWS::IAM::ManagedPolicy");
    const statements = Object.values(policies)
      .filter((p) =>
        JSON.stringify((p as { Properties: { Roles: unknown } }).Properties.Roles).includes(roleId),
      )
      .flatMap(
        (p) =>
          (p as { Properties: { PolicyDocument: { Statement: Statement[] } } }).Properties.PolicyDocument
            .Statement,
      );
    const actions = actionsOf(statements);
    const allowed = new Set([
      ...PORTAL_API_REGISTRY_ACTIONS,
      ...PORTAL_API_PIPELINE_ACTIONS,
      ...PORTAL_API_GUARDRAIL_ACTIONS,
      "sts:AssumeRole",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "xray:PutTraceSegments",
      "xray:PutTelemetryRecords",
    ]);
    for (const action of actions) expect(allowed.has(action)).toBe(true);
    const assume = statements.find((s) => s.Sid === "PortalAssumeFleetReader")!;
    expect(JSON.stringify(assume.Resource)).toContain(
      `:iam::${CELL}:role/AgenticAI-PortalFleetReader-nonprod`,
    );
    expect(JSON.stringify(assume.Resource)).not.toContain('"*"');
    const ownTelemetry = new Set(["logs:CreateLogStream", "logs:PutLogEvents", "xray:PutTraceSegments", "xray:PutTelemetryRecords"]);
    for (const action of actions.filter((a) => !ownTelemetry.has(a))) {
      expect(action).not.toMatch(/:(Create|Update|Delete|Put|Tag|Untag|Invoke|Approve|Submit|Associate)/);
    }
  });

  it("exposes GET routes only, with the JWT authorizer on every data route", () => {
    const routes = Object.values(template.findResources("AWS::ApiGatewayV2::Route")).map(
      (r) => (r as { Properties: { RouteKey: string; AuthorizationType: string } }).Properties,
    );
    expect(routes.map((r) => r.RouteKey).sort()).toEqual(["GET /api/v1/health", "GET /api/v1/{proxy+}"]);
    expect(routes.find((r) => r.RouteKey === "GET /api/v1/{proxy+}")!.AuthorizationType).toBe("JWT");
    expect(routes.find((r) => r.RouteKey === "GET /api/v1/health")!.AuthorizationType).toBe("NONE");
    template.resourceCountIs("AWS::ApiGatewayV2::Authorizer", 1);
    template.hasResourceProperties("AWS::ApiGatewayV2::Stage", {
      AccessLogSettings: Match.objectLike({ DestinationArn: Match.anyValue() }),
    });
  });

  it("limits browser access to the portal origin and GET", () => {
    template.hasResourceProperties("AWS::ApiGatewayV2::Api", {
      CorsConfiguration: Match.objectLike({ AllowMethods: ["GET", "OPTIONS"] }),
    });
  });

  it("hosts the web application privately behind CloudFront with the edge web ACL", () => {
    template.hasResourceProperties("AWS::CloudFront::Distribution", {
      DistributionConfig: Match.objectLike({ WebACLId: WEB_ACL, DefaultRootObject: "index.html" }),
    });
    template.resourceCountIs("AWS::CloudFront::OriginAccessControl", 1);
    const buckets = template.findResources("AWS::S3::Bucket");
    for (const bucket of Object.values(buckets)) {
      expect((bucket as { Properties: Record<string, unknown> }).Properties.PublicAccessBlockConfiguration).toEqual({
        BlockPublicAcls: true,
        BlockPublicPolicy: true,
        IgnorePublicAcls: true,
        RestrictPublicBuckets: true,
      });
    }
  });

  it("creates the Cognito user pool with MFA, no self sign-up, PKCE code flow and one group per persona", () => {
    template.hasResourceProperties("AWS::Cognito::UserPool", {
      MfaConfiguration: "ON",
      AdminCreateUserConfig: { AllowAdminCreateUserOnly: true },
    });
    template.hasResourceProperties("AWS::Cognito::UserPoolClient", {
      GenerateSecret: false,
      AllowedOAuthFlows: ["code"],
    });
    template.resourceCountIs("AWS::Cognito::UserPoolGroup", Object.keys(PORTAL_COGNITO_GROUPS).length);
  });

  it("creates no resource that can change a Workstream cell", () => {
    const types = new Set(
      Object.values(template.toJSON().Resources as Record<string, { Type: string }>).map((r) => r.Type),
    );
    for (const type of types) {
      expect(type).not.toMatch(/^AWS::(BedrockAgentCore|AgentRegistry|Organizations|CodePipeline)::/);
    }
  });

  it("passes cdk-nag", () => {
    expect(nagErrors(stack)).toEqual([]);
  });
});

describe("Phase 27 — Microsoft Entra ID sign-in", () => {
  const stack = portalStack("entra");
  const template = Template.fromStack(stack);

  it("creates no user pool and validates tokens against the tenant issuer", () => {
    template.resourceCountIs("AWS::Cognito::UserPool", 0);
    template.hasResourceProperties("AWS::ApiGatewayV2::Authorizer", {
      AuthorizerType: "JWT",
      JwtConfiguration: {
        Audience: [ENTRA.apiAudience],
        Issuer: `https://login.microsoftonline.com/${ENTRA.tenantId}/v2.0`,
      },
    });
  });

  it("refuses incomplete Entra settings", () => {
    const app = new App();
    expect(
      () =>
        new AgentFactoryPortalStack(app, "BadEntra", {
          env: { account: PLATFORM, region: REGION },
          environment: "nonprod",
          identityProvider: "entra",
          entra: { ...ENTRA, tenantId: "not-a-guid" },
          webAclArn: WEB_ACL,
          cells: [],
          apiCodePath: apiCode,
          webDistPath: webDist,
        }),
    ).toThrow(/tenantId must be a GUID/);
  });

  it("passes cdk-nag", () => {
    expect(nagErrors(stack)).toEqual([]);
  });
});

describe("Phase 27 — edge web ACL", () => {
  it("blocks sources outside the allow list and adds rate limiting and managed rules", () => {
    const template = Template.fromStack(edgeStack());
    template.hasResourceProperties("AWS::WAFv2::WebACL", {
      Scope: "CLOUDFRONT",
      Rules: Match.arrayWith([
        Match.objectLike({ Name: "BlockSourcesOutsideAllowList", Action: { Block: {} } }),
        Match.objectLike({ Name: "RateLimitPerSource" }),
        Match.objectLike({ Name: "AWSManagedRulesCommonRuleSet" }),
      ]),
    });
    template.resourceCountIs("AWS::WAFv2::IPSet", 1);
    template.hasResourceProperties("AWS::WAFv2::LoggingConfiguration", {
      RedactedFields: Match.arrayWith([{ SingleHeader: { Name: "authorization" } }]),
    });
  });

  it("must live in us-east-1 and rejects malformed CIDRs", () => {
    const app = new App();
    expect(
      () =>
        new AgentFactoryPortalEdgeStack(app, "WrongRegion", {
          env: { account: PLATFORM, region: REGION },
          environment: "nonprod",
          allowedIpv4Cidrs: ["198.51.100.0/24"],
        }),
    ).toThrow(/us-east-1/);
    expect(() => edgeStack(["not-a-cidr"])).toThrow(/not an IPv4 CIDR/);
  });

  it("passes cdk-nag", () => {
    expect(nagErrors(edgeStack())).toEqual([]);
  });
});

describe("Phase 27 — stage routing is opt-in", () => {
  it("handles only the three portal stages", () => {
    expect([...AGENT_FACTORY_PORTAL_STAGES]).toEqual([
      "agent-factory-portal-edge",
      "agent-factory-portal",
      "agent-factory-portal-fleet-reader",
    ]);
    expect(addAgentFactoryPortalStage(new App(), "platform", REGION)).toBe(false);
  });

  it("requires an allow list unless exposure is explicitly public", () => {
    const app = new App({
      context: {
        "agenticai/portalEnvironment": "nonprod",
        "agenticai/portalAccountId": PLATFORM,
      },
    });
    expect(() => addAgentFactoryPortalStage(app, "agent-factory-portal-edge", REGION)).toThrow(
      /portalAllowedCidrs/,
    );
  });

  it("fails with a build hint when the application bundles are missing", () => {
    const app = new App({
      context: {
        "agenticai/portalEnvironment": "nonprod",
        "agenticai/portalAccountId": PLATFORM,
        "agenticai/portalWebAclArn": WEB_ACL,
        "agenticai/portalApiCodePath": path.join(assets, "missing"),
        "agenticai/portalWebDistPath": webDist,
      },
    });
    expect(() => addAgentFactoryPortalStage(app, "agent-factory-portal", REGION)).toThrow(
      /Build it first/,
    );
  });

  it("builds the portal from context", () => {
    const app = new App({
      context: {
        "agenticai/portalEnvironment": "nonprod",
        "agenticai/portalAccountId": PLATFORM,
        "agenticai/portalWebAclArn": WEB_ACL,
        "agenticai/portalApiCodePath": apiCode,
        "agenticai/portalWebDistPath": webDist,
        "agenticai/portalCells": JSON.stringify([
          { tenantId: "shared", agentId: "shared", accountId: CELL, region: REGION, externalId: EXTERNAL_ID },
        ]),
      },
    });
    expect(addAgentFactoryPortalStage(app, "agent-factory-portal", REGION)).toBe(true);
    const stack = app.node.findChild("AgenticAI-AgentFactoryPortal-nonprod") as Stack;
    Template.fromStack(stack).hasResourceProperties("AWS::Lambda::Function", {
      Handler: "handler.handler",
      Tags: Match.arrayWith([{ Key: "application-id", Value: "agent-factory-portal" }]),
    });
  });
});
