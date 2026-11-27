/**
 * Phase 28 conformance — Agent Factory Portal governed registration and
 * approval (opt-in).
 *
 * Pins separation of duties in IAM, not only in the authorization core:
 *   - the registrar function can create, change, submit and delete records
 *     and cannot decide an approval;
 *   - the approver function can decide an approval and cannot create or
 *     change a record;
 *   - the audit trail is append-only for both (PutItem and Query, nothing
 *     that rewrites or deletes), and the read API can only query it;
 *   - the read API role gains no mutating action;
 *   - every write route requires the JWT authorizer and goes to the function
 *     whose role holds that authority;
 *   - without the opt-in, none of this exists.
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
  PORTAL_APPROVER_REGISTRY_ACTIONS,
  PORTAL_REGISTRAR_REGISTRY_ACTIONS,
} from "@agenticai/agent-factory-portal";
import { AgentFactoryPortalStack } from "../../apps/platform-account/lib/agent-factory-portal-stack";
import { addAgentFactoryPortalStage } from "../../apps/platform-account/lib/agent-factory-portal-stages";

const PLATFORM = "222222222222";
const REGION = "eu-west-1";
const WEB_ACL = `arn:aws:wafv2:us-east-1:${PLATFORM}:global/webacl/portal/11111111-2222-4333-8444-555555555555`;
const REGISTRY_ID = "abcdEFGH1234ijkl";
const REGISTRY_ARN = `arn:aws:agent-registry:${REGION}:${PLATFORM}:registry/${REGISTRY_ID}`;

const assets = fs.mkdtempSync(path.join(os.tmpdir(), "portal-actions-conformance-"));
const apiCode = path.join(assets, "api");
const webDist = path.join(assets, "web");
fs.mkdirSync(apiCode);
fs.mkdirSync(webDist);
for (const name of ["handler.py", "registrar_handler.py", "approver_handler.py"]) {
  fs.writeFileSync(path.join(apiCode, name), "def handler(event, context):\n    return {}\n");
}
fs.writeFileSync(path.join(webDist, "index.html"), "<!doctype html><title>portal</title>\n");

afterAll(() => {
  fs.rmSync(assets, { recursive: true, force: true });
});

function portal(governed: boolean): AgentFactoryPortalStack {
  const app = new App();
  Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true }));
  Aspects.of(app).add(new NIST80053R5Checks({ verbose: true }));
  return new AgentFactoryPortalStack(app, "Portal", {
    env: { account: PLATFORM, region: REGION },
    environment: "nonprod",
    identityProvider: "cognito",
    webAclArn: WEB_ACL,
    cells: [],
    apiCodePath: apiCode,
    webDistPath: webDist,
    registry: { id: REGISTRY_ID, arn: REGISTRY_ARN },
    governedActions: governed ? { groupTenantMap: { "product-teams": ["ws1"] } } : undefined,
  });
}

type Statement = { Action: string | string[]; Resource: unknown; Sid?: string };
type Policy = { Properties: { Roles: unknown; PolicyDocument: { Statement: Statement[] } } };

function actionsOfRole(template: Template, roleName: string): string[] {
  const roles = template.findResources("AWS::IAM::Role", { Properties: { RoleName: roleName } });
  expect(Object.keys(roles)).toHaveLength(1);
  const roleId = Object.keys(roles)[0];
  return Object.values(template.findResources("AWS::IAM::ManagedPolicy") as Record<string, Policy>)
    .filter((p) => JSON.stringify(p.Properties.Roles).includes(roleId))
    .flatMap((p) => p.Properties.PolicyDocument.Statement)
    .flatMap((s) => (Array.isArray(s.Action) ? s.Action : [s.Action]));
}

const OWN_TELEMETRY = ["logs:CreateLogStream", "logs:PutLogEvents", "xray:PutTraceSegments", "xray:PutTelemetryRecords"];

describe("Phase 28 — separation of duties in IAM", () => {
  const stack = portal(true);
  const template = Template.fromStack(stack);
  const registrar = actionsOfRole(template, "AgenticAI-RegistryRegistrar-nonprod");
  const approver = actionsOfRole(template, "AgenticAI-RegistryApprover-nonprod");
  const reader = actionsOfRole(template, "AgenticAI-PortalApi-nonprod");

  it("registrar can create, change, submit and delete records, and cannot decide an approval", () => {
    expect([...registrar].sort()).toEqual(
      [...PORTAL_REGISTRAR_REGISTRY_ACTIONS, "dynamodb:PutItem", "dynamodb:Query", ...OWN_TELEMETRY].sort(),
    );
    expect(registrar).not.toContain("agent-registry:UpdateRegistryRecordStatus");
  });

  it("approver can decide an approval, and cannot create, change or delete a record", () => {
    expect([...approver].sort()).toEqual(
      [...PORTAL_APPROVER_REGISTRY_ACTIONS, "dynamodb:PutItem", "dynamodb:Query", ...OWN_TELEMETRY].sort(),
    );
    for (const forbidden of [
      "agent-registry:CreateRegistryRecord",
      "agent-registry:UpdateRegistryRecord",
      "agent-registry:DeleteRegistryRecord",
      "agent-registry:SubmitRegistryRecordForApproval",
    ]) {
      expect(approver).not.toContain(forbidden);
    }
  });

  it("no function can rewrite or delete the audit trail", () => {
    for (const actions of [registrar, approver, reader]) {
      for (const action of actions.filter((a) => a.startsWith("dynamodb:"))) {
        expect(["dynamodb:PutItem", "dynamodb:Query"]).toContain(action);
      }
    }
    expect(reader.filter((a) => a.startsWith("dynamodb:"))).toEqual(["dynamodb:Query"]);
  });

  it("the read API role still holds no mutating Registry action", () => {
    for (const action of reader.filter((a) => a.startsWith("agent-registry:"))) {
      expect(action).toMatch(/:(Get|List)/);
    }
  });

  it("Registry permissions are scoped to the one Registry and its records", () => {
    const statements = Object.values(template.findResources("AWS::IAM::ManagedPolicy") as Record<string, Policy>)
      .flatMap((p) => p.Properties.PolicyDocument.Statement)
      .filter((s) => s.Sid === "RegistryRecords");
    expect(statements).toHaveLength(2);
    for (const statement of statements) {
      expect(statement.Resource).toEqual([REGISTRY_ARN, `${REGISTRY_ARN}/record/*`]);
    }
  });

  it("keeps the audit trail recoverable", () => {
    template.hasResourceProperties("AWS::DynamoDB::Table", {
      PointInTimeRecoverySpecification: { PointInTimeRecoveryEnabled: true },
      KeySchema: [
        { AttributeName: "pk", KeyType: "HASH" },
        { AttributeName: "sk", KeyType: "RANGE" },
      ],
    });
  });

  it("passes cdk-nag", () => {
    const errors = Annotations.fromStack(stack)
      .findError("*", Match.stringLikeRegexp("(AwsSolutions|NIST\\.800\\.53\\.R5)-.*"))
      .map((entry) => `${entry.id}: ${String(entry.entry.data).split("\n")[0]}`);
    expect(errors).toEqual([]);
  });
});

describe("Phase 28 — write routes", () => {
  const template = Template.fromStack(portal(true));
  const json = template.toJSON() as { Resources: Record<string, { Type: string; Properties: Record<string, unknown> }> };

  function functionOfRoute(routeKey: string): string {
    const route = Object.values(json.Resources).find(
      (r) => r.Type === "AWS::ApiGatewayV2::Route" && r.Properties.RouteKey === routeKey,
    );
    expect(route).toBeDefined();
    expect(route!.Properties.AuthorizationType).toBe("JWT");
    const integrationId = JSON.stringify(route!.Properties.Target).match(/"Ref":"([^"]+)"/)![1];
    const functionId = JSON.stringify(json.Resources[integrationId].Properties.IntegrationUri).match(
      /"Fn::GetAtt":\["([^"]+)"/,
    )![1];
    return String(json.Resources[functionId].Properties.Handler);
  }

  it.each([
    ["POST /api/v1/registrations", "registrar_handler.handler"],
    ["PUT /api/v1/registrations/{record_id}", "registrar_handler.handler"],
    ["DELETE /api/v1/registrations/{record_id}", "registrar_handler.handler"],
    ["POST /api/v1/registrations/{record_id}/submit", "registrar_handler.handler"],
    ["POST /api/v1/registrations/{record_id}/approve", "approver_handler.handler"],
    ["POST /api/v1/registrations/{record_id}/reject", "approver_handler.handler"],
  ])("%s is authorized and served by %s", (routeKey, handler) => {
    expect(functionOfRoute(routeKey)).toBe(handler);
  });

  it("the read function serves GET only", () => {
    const readRoutes = Object.values(json.Resources)
      .filter((r) => r.Type === "AWS::ApiGatewayV2::Route")
      .map((r) => String(r.Properties.RouteKey))
      .filter((key) => functionOfRouteOrUndefined(key) === "handler.handler");
    expect(readRoutes.sort()).toEqual(["GET /api/v1/health", "GET /api/v1/{proxy+}"]);
  });

  function functionOfRouteOrUndefined(routeKey: string): string | undefined {
    const route = Object.values(json.Resources).find(
      (r) => r.Type === "AWS::ApiGatewayV2::Route" && r.Properties.RouteKey === routeKey,
    )!;
    const integrationId = JSON.stringify(route.Properties.Target).match(/"Ref":"([^"]+)"/)![1];
    const functionId = JSON.stringify(json.Resources[integrationId].Properties.IntegrationUri).match(
      /"Fn::GetAtt":\["([^"]+)"/,
    )![1];
    return String(json.Resources[functionId].Properties.Handler);
  }

  it("tells the web application whether the actions are on", () => {
    expect(portal(true).webConfig.features).toEqual({ readOnly: false, governedActions: true });
    expect(portal(false).webConfig.features).toEqual({ readOnly: true, governedActions: false });
  });
});

describe("Phase 28 — opt-in", () => {
  it("creates no write route, role or table without the opt-in", () => {
    const template = Template.fromStack(portal(false));
    template.resourceCountIs("AWS::DynamoDB::Table", 0);
    expect(
      Object.keys(
        template.findResources("AWS::IAM::Role", {
          Properties: { RoleName: Match.stringLikeRegexp("AgenticAI-Registry(Registrar|Approver)-.*") },
        }),
      ),
    ).toHaveLength(0);
    const routes = Object.values(template.findResources("AWS::ApiGatewayV2::Route")).map(
      (r) => (r as { Properties: { RouteKey: string } }).Properties.RouteKey,
    );
    expect(routes.every((key) => key.startsWith("GET "))).toBe(true);
    template.hasResourceProperties("AWS::ApiGatewayV2::Api", {
      CorsConfiguration: Match.objectLike({ AllowMethods: ["GET", "OPTIONS"] }),
    });
  });

  it("validates the tenant map and the Registry override from context", () => {
    const base = {
      "agenticai/portalEnvironment": "nonprod",
      "agenticai/portalAccountId": PLATFORM,
      "agenticai/portalWebAclArn": WEB_ACL,
      "agenticai/portalApiCodePath": apiCode,
      "agenticai/portalWebDistPath": webDist,
      "agenticai/portalGovernedActions": "true",
    };
    expect(() =>
      addAgentFactoryPortalStage(
        new App({ context: { ...base, "agenticai/portalGroupTenantMap": '{"product-teams":"ws1"}' } }),
        "agent-factory-portal",
        REGION,
      ),
    ).toThrow(/must map to a list of tenant ids/);
    expect(() =>
      addAgentFactoryPortalStage(
        new App({
          context: {
            ...base,
            "agenticai/portalRegistryId": REGISTRY_ID,
            "agenticai/portalRegistryArn": `arn:aws:agent-registry:${REGION}:${PLATFORM}:registry/otherRegistry0001`,
          },
        }),
        "agent-factory-portal",
        REGION,
      ),
    ).toThrow(/must be the ARN of the Registry named by/);
    const app = new App({
      context: {
        ...base,
        "agenticai/portalGroupTenantMap": '{"product-teams":["ws1"]}',
        "agenticai/portalRegistryId": REGISTRY_ID,
        "agenticai/portalRegistryArn": REGISTRY_ARN,
      },
    });
    expect(addAgentFactoryPortalStage(app, "agent-factory-portal", REGION)).toBe(true);
    const stack = app.node.findChild("AgenticAI-AgentFactoryPortal-nonprod") as Stack;
    Template.fromStack(stack).resourceCountIs("AWS::DynamoDB::Table", 1);
  });
});
