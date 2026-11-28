/**
 * Phase 29 conformance — Agent Factory Portal: incident containment, the
 * organization discovery Registry, and the external inventory reader.
 *
 * Containment is the one deliberate exception to "central visibility must not
 * become central write access". This suite pins how narrow it is:
 *   - a cell is containable only when it deploys the target role;
 *   - the target role holds five actions on that cell's Runtimes (resource
 *     policy read, put and delete; stop a session; list endpoints), may find
 *     the sessions in the names of the Runtimes' log streams, and trusts only
 *     the portal's containment function role, with the cell's external id.
 *     It cannot run a query: a role that can query the spans log group can
 *     read span content, so that second source of session ids is a separate,
 *     explicit opt-in;
 *   - the containment function's own role can only assume those target roles,
 *     read one record of the agent Registry and append to and read the audit
 *     trail: no AgentCore permission of its own, and no Registry write;
 *   - the write routes go to that function, behind the JWT authorizer;
 *   - without a containable cell the function, role and routes do not exist.
 *
 * The external inventory reader is read-only by construction: no invoke, no
 * data access, no change, assumed with an external id and no access key.
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
  PORTAL_CONTAINMENT_REGISTRY_ACTIONS,
  PORTAL_CONTAINMENT_TARGET_ACTIONS,
  PORTAL_EXTERNAL_READER_AGENTCORE_ACTIONS,
  PORTAL_EXTERNAL_READER_METRIC_ACTIONS,
  PortalCell,
} from "@agenticai/agent-factory-portal";
import { AgentFactoryPortalStack } from "../../apps/platform-account/lib/agent-factory-portal-stack";
import { addAgentFactoryPortalStage } from "../../apps/platform-account/lib/agent-factory-portal-stages";
import {
  AgentFactoryPortalContainmentStack,
  AgentFactoryPortalExternalReaderStack,
} from "../../apps/workload-account/lib/agent-factory-portal-fleet-reader-stack";

const PLATFORM = "222222222222";
const CELL = "444444444444";
const EXTERNAL = "999999999999";
const REGION = "eu-west-1";
const WEB_ACL = `arn:aws:wafv2:us-east-1:${PLATFORM}:global/webacl/portal/11111111-2222-4333-8444-555555555555`;
const EXTERNAL_ID = "portal-external-id-0123456789";
const AGENT_REGISTRY = { id: "mnopQRST5678uvwx", arn: `arn:aws:agent-registry:${REGION}:${PLATFORM}:registry/mnopQRST5678uvwx` };
const DISCOVERY_REGISTRY = { id: "abcdEFGH1234ijkl", arn: `arn:aws:agent-registry:${REGION}:${PLATFORM}:registry/abcdEFGH1234ijkl` };

const assets = fs.mkdtempSync(path.join(os.tmpdir(), "portal-containment-conformance-"));
const apiCode = path.join(assets, "api");
const webDist = path.join(assets, "web");
fs.mkdirSync(apiCode);
fs.mkdirSync(webDist);
for (const name of ["handler.py", "registrar_handler.py", "approver_handler.py", "containment_handler.py"]) {
  fs.writeFileSync(path.join(apiCode, name), "def handler(event, context):\n    return {}\n");
}
fs.writeFileSync(path.join(webDist, "index.html"), "<!doctype html><title>portal</title>\n");
afterAll(() => fs.rmSync(assets, { recursive: true, force: true }));

function withNag(app: App): App {
  Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true }));
  Aspects.of(app).add(new NIST80053R5Checks({ verbose: true }));
  return app;
}

function nagErrors(stack: Stack): string[] {
  return Annotations.fromStack(stack)
    .findError("*", Match.stringLikeRegexp("(AwsSolutions|NIST\\.800\\.53\\.R5)-.*"))
    .map((entry) => `${entry.id}: ${String(entry.entry.data).split("\n")[0]}`);
}

function cell(overrides: Partial<PortalCell> = {}): PortalCell {
  return {
    tenantId: "ws1",
    agentId: "travel-agent",
    environment: "nonprod",
    accountId: CELL,
    region: REGION,
    externalId: EXTERNAL_ID,
    ...overrides,
  };
}

/** PORTAL_CELLS is a token-joined string when it holds an account-derived ARN; resolve the literal parts. */
function resolveJoin(value: unknown): string {
  const join = (value as { "Fn::Join": [string, unknown[]] })["Fn::Join"];
  return join[1].map((part) => (typeof part === "string" ? part : "aws")).join(join[0]);
}

function portal(cells: PortalCell[]): AgentFactoryPortalStack {
  return new AgentFactoryPortalStack(withNag(new App()), "Portal", {
    env: { account: PLATFORM, region: REGION },
    environment: "nonprod",
    identityProvider: "cognito",
    webAclArn: WEB_ACL,
    cells,
    apiCodePath: apiCode,
    webDistPath: webDist,
    governedActions: { groupTenantMap: { "product-teams": ["ws1"] } },
    agentRegistry: AGENT_REGISTRY,
    discoveryRegistry: DISCOVERY_REGISTRY,
    ownerGroups: ["travel-platform"],
    inactiveDays: 14,
  });
}

type Statement = { Action: string | string[]; Resource: unknown; Sid?: string; Condition?: unknown };
type Policy = { Properties: { Roles: unknown; PolicyDocument: { Statement: Statement[] } } };

function statementsOfRole(template: Template, roleName: string): Statement[] {
  const roles = template.findResources("AWS::IAM::Role", { Properties: { RoleName: roleName } });
  expect(Object.keys(roles)).toHaveLength(1);
  const roleId = Object.keys(roles)[0];
  return Object.values(template.findResources("AWS::IAM::ManagedPolicy") as Record<string, Policy>)
    .filter((p) => JSON.stringify(p.Properties.Roles).includes(roleId))
    .flatMap((p) => p.Properties.PolicyDocument.Statement);
}

const actions = (statements: Statement[]): string[] =>
  statements.flatMap((s) => (Array.isArray(s.Action) ? s.Action : [s.Action]));

describe("Phase 29 — containment target role (Workstream cell)", () => {
  const stack = new AgentFactoryPortalContainmentStack(withNag(new App()), "Target", {
    env: { account: CELL, region: REGION },
    environment: "nonprod",
    platformAccountId: PLATFORM,
    externalId: EXTERNAL_ID,
  });
  const template = Template.fromStack(stack);
  const statements = statementsOfRole(template, "AgenticAI-PortalContainmentTarget-nonprod");

  it("holds exactly the five containment actions on this cell's Runtimes, and the two reads that find sessions", () => {
    expect([...PORTAL_CONTAINMENT_TARGET_ACTIONS].sort()).toEqual([
      "bedrock-agentcore:DeleteResourcePolicy",
      "bedrock-agentcore:GetResourcePolicy",
      "bedrock-agentcore:ListAgentRuntimeEndpoints",
      "bedrock-agentcore:PutResourcePolicy",
      "bedrock-agentcore:StopRuntimeSession",
    ]);
    const runtime = statements.find((s) => s.Sid === "ContainRuntimes")!;
    expect(actions([runtime]).sort()).toEqual([...PORTAL_CONTAINMENT_TARGET_ACTIONS].sort());
    expect(JSON.stringify(runtime.Resource)).toContain(`:bedrock-agentcore:${REGION}:${CELL}:runtime/*`);
    expect(JSON.stringify(runtime.Resource)).not.toMatch(/gateway|memory|"\*"/);
    // By default: those five, and the names of session log streams. No query, so no span content.
    expect(actions(statements).sort()).toEqual([...PORTAL_CONTAINMENT_TARGET_ACTIONS, "logs:DescribeLogStreams"].sort());
    expect(statements.map((s) => s.Sid).sort()).toEqual(["ContainRuntimes", "FindRuntimeSessionStreams"]);
  });

  it("can query the spans log group only when the cell asks for that source of session ids", () => {
    const optIn = new AgentFactoryPortalContainmentStack(withNag(new App()), "TargetWithSpans", {
      env: { account: CELL, region: REGION },
      environment: "nonprod",
      platformAccountId: PLATFORM,
      externalId: EXTERNAL_ID,
      spanSessionDiscovery: true,
    });
    const withSpans = statementsOfRole(Template.fromStack(optIn), "AgenticAI-PortalContainmentTarget-nonprod");
    expect(actions(withSpans).sort()).toEqual(
      [...PORTAL_CONTAINMENT_TARGET_ACTIONS, "logs:DescribeLogStreams", "logs:StartQuery", "logs:GetQueryResults"].sort(),
    );
    const query = withSpans.find((s) => s.Sid === "FindRuntimeSessionsInSpans")!;
    expect(JSON.stringify(query.Resource)).toContain(`:logs:${REGION}:${CELL}:log-group:aws/spans:*`);
    const results = withSpans.find((s) => s.Sid === "ReadSessionQueryResults")!;
    expect(results.Condition).toEqual({ StringEquals: { "aws:RequestedRegion": REGION } });
    expect(nagErrors(optIn)).toEqual([]);
  });

  it("lists session log stream names only in the log groups of this cell's Runtimes", () => {
    const streams = statements.find((s) => s.Sid === "FindRuntimeSessionStreams")!;
    expect(streams.Action).toBe("logs:DescribeLogStreams");
    const resource = JSON.stringify(streams.Resource);
    expect(resource).toContain(`:logs:${REGION}:${CELL}:log-group:/aws/bedrock-agentcore/runtimes/*`);
    expect(resource).not.toContain("log-group:*");
  });

  it("cannot invoke, change or delete a Runtime, read a log event, or touch anything else", () => {
    for (const action of actions(statements)) {
      expect(action).not.toMatch(/:(Invoke|Update|Create|DeleteAgentRuntime|Tag|ListSessions)/);
      expect(action).not.toMatch(
        /^logs:(GetLogEvents|FilterLogEvents|GetLogRecord|StartLiveTail|StartQuery|GetQueryResults|Put|Create|Delete)/,
      );
      expect(action.startsWith("bedrock-agentcore:") || action.startsWith("logs:")).toBe(true);
    }
  });

  it("trusts only the portal containment role, with the external id", () => {
    template.hasResourceProperties("AWS::IAM::Role", {
      RoleName: "AgenticAI-PortalContainmentTarget-nonprod",
      AssumeRolePolicyDocument: {
        Statement: [
          Match.objectLike({
            Action: "sts:AssumeRole",
            Condition: {
              ArnEquals: {
                "aws:PrincipalArn": {
                  "Fn::Join": ["", Match.arrayWith([`:iam::${PLATFORM}:role/AgenticAI-PortalContainment-nonprod`])],
                },
              },
              StringEquals: { "sts:ExternalId": EXTERNAL_ID },
            },
          }),
        ],
      },
    });
  });

  it("passes cdk-nag", () => {
    expect(nagErrors(stack)).toEqual([]);
  });

  it("is deployed by its own stage: no query by default, and the spans option honours a custom log group", () => {
    const base = {
      "agenticai/portalEnvironment": "nonprod",
      "agenticai/portalAccountId": PLATFORM,
      "agenticai/portalCellAccountId": CELL,
      "agenticai/portalExternalId": EXTERNAL_ID,
      "agenticai/portalSpansLogGroupNames": "custom/agent-spans",
    };
    const staged = (context: Record<string, string>): Statement[] => {
      const app = new App({ context });
      expect(addAgentFactoryPortalStage(app, "agent-factory-portal-containment", REGION)).toBe(true);
      const template = Template.fromStack(app.node.findChild("AgenticAI-AgentFactoryPortal-Containment-nonprod") as Stack);
      return statementsOfRole(template, "AgenticAI-PortalContainmentTarget-nonprod");
    };
    // Naming a spans log group does not grant a query on it.
    expect(actions(staged(base)).some((a) => a === "logs:StartQuery")).toBe(false);
    const query = staged({ ...base, "agenticai/portalContainmentSpans": "true" }).find(
      (s) => s.Sid === "FindRuntimeSessionsInSpans",
    )!;
    expect(JSON.stringify(query.Resource)).toContain(`:logs:${REGION}:${CELL}:log-group:custom/agent-spans:*`);
    expect(JSON.stringify(query.Resource)).not.toContain("aws/spans");
    expect(() => staged({ ...base, "agenticai/portalContainmentSpans": "yes" })).toThrow(/must be true or false/);
  });

  it("refuses to synthesize without the cell's external id", () => {
    const app = new App({
      context: {
        "agenticai/portalEnvironment": "nonprod",
        "agenticai/portalAccountId": PLATFORM,
        "agenticai/portalCellAccountId": CELL,
      },
    });
    expect(() => addAgentFactoryPortalStage(app, "agent-factory-portal-containment", REGION)).toThrow(
      /requires context 'agenticai\/portalExternalId'/,
    );
  });
});

describe("Phase 29 — containment function (Platform account)", () => {
  const stack = portal([cell({ containment: true }), cell({ tenantId: "ws2", accountId: "555555555555" })]);
  const template = Template.fromStack(stack);
  const statements = statementsOfRole(template, "AgenticAI-PortalContainment-nonprod");

  it("can only assume the target role of cells that deployed one, read one Registry record, and use the audit trail", () => {
    const allowed = new Set([
      "sts:AssumeRole",
      "agent-registry:GetRegistryRecord",
      "dynamodb:PutItem",
      "dynamodb:Query",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "xray:PutTraceSegments",
      "xray:PutTelemetryRecords",
    ]);
    for (const action of actions(statements)) expect(allowed.has(action)).toBe(true);
    const assume = statements.find((s) => s.Sid === "AssumeCellContainmentTarget")!;
    expect(JSON.stringify(assume.Resource)).toContain(`:iam::${CELL}:role/AgenticAI-PortalContainmentTarget-nonprod`);
    // The cell that did not opt in is not reachable.
    expect(JSON.stringify(assume.Resource)).not.toContain("555555555555");
    expect(actions(statements).some((a) => a.startsWith("bedrock-agentcore:"))).toBe(false);
    // The Registry is read, never written, and only the agent Registry.
    expect([...PORTAL_CONTAINMENT_REGISTRY_ACTIONS]).toEqual(["agent-registry:GetRegistryRecord"]);
    const registry = statements.filter((s) => actions([s]).some((a) => a.startsWith("agent-registry:")));
    expect(registry).toHaveLength(1);
    expect(actions(registry)).toEqual(["agent-registry:GetRegistryRecord"]);
    expect(JSON.stringify(registry[0].Resource)).toContain(AGENT_REGISTRY.arn);
    expect(JSON.stringify(registry[0].Resource)).not.toContain(DISCOVERY_REGISTRY.arn);
  });

  it("tells the functions about the spans option only for a cell that has containment and asked for it", () => {
    const cellsOf = (portalStack: AgentFactoryPortalStack): Array<Record<string, unknown>> => {
      const functions = Object.values(Template.fromStack(portalStack).findResources("AWS::Lambda::Function")).map(
        (f) => (f as { Properties: { Handler: string; Environment?: { Variables: Record<string, unknown> } } }).Properties,
      );
      const raw = functions.find((f) => f.Handler === "containment_handler.handler")!.Environment!.Variables.PORTAL_CELLS;
      return JSON.parse(typeof raw === "string" ? raw : resolveJoin(raw)) as Array<Record<string, unknown>>;
    };
    const [contained, other] = cellsOf(
      portal([cell({ containment: true, containmentSpans: true }), cell({ tenantId: "ws2", accountId: "555555555555" })]),
    );
    expect(contained.containmentSpans).toBe(true);
    expect(String(contained.containmentRoleArn)).toContain("AgenticAI-PortalContainmentTarget-nonprod");
    expect(other.containmentSpans).toBeUndefined();
    expect(other.containmentRoleArn).toBeUndefined();
    // Without the option nothing is said: the default is stream names only.
    for (const configured of cellsOf(stack)) expect(configured.containmentSpans).toBeUndefined();
  });

  it("refuses the spans option on a cell that did not enable containment", () => {
    const app = new App({
      context: {
        "agenticai/portalEnvironment": "nonprod",
        "agenticai/portalAccountId": PLATFORM,
        "agenticai/portalWebAclArn": WEB_ACL,
        "agenticai/portalApiCodePath": apiCode,
        "agenticai/portalWebDistPath": webDist,
        "agenticai/portalCells": JSON.stringify([
          { tenantId: "ws1", agentId: "a", accountId: CELL, region: REGION, externalId: EXTERNAL_ID, containmentSpans: true },
        ]),
      },
    });
    expect(() => addAgentFactoryPortalStage(app, "agent-factory-portal", REGION)).toThrow(
      /containmentSpans needs containment: true/,
    );
  });

  it("gives the containment function more reserved concurrency than the registration functions", () => {
    const functions = Object.values(template.findResources("AWS::Lambda::Function")).map(
      (f) => (f as { Properties: { Handler: string; ReservedConcurrentExecutions?: number } }).Properties,
    );
    expect(functions.find((f) => f.Handler === "containment_handler.handler")!.ReservedConcurrentExecutions).toBe(20);
    expect(functions.find((f) => f.Handler === "approver_handler.handler")!.ReservedConcurrentExecutions).toBe(5);
  });

  it("serves the two containment routes behind the JWT authorizer", () => {
    const json = template.toJSON() as { Resources: Record<string, { Type: string; Properties: Record<string, unknown> }> };
    for (const action of ["contain", "release"]) {
      const route = Object.values(json.Resources).find(
        (r) =>
          r.Type === "AWS::ApiGatewayV2::Route" &&
          r.Properties.RouteKey === `POST /api/v1/agents/{agent_id}/containment/${action}`,
      )!;
      expect(route).toBeDefined();
      expect(route.Properties.AuthorizationType).toBe("JWT");
      const integrationId = JSON.stringify(route.Properties.Target).match(/"Ref":"([^"]+)"/)![1];
      const functionId = JSON.stringify(json.Resources[integrationId].Properties.IntegrationUri).match(
        /"Fn::GetAtt":\["([^"]+)"/,
      )![1];
      expect(json.Resources[functionId].Properties.Handler).toBe("containment_handler.handler");
    }
  });

  it("gives the read API the discovery Registry, the owner roster and the inactivity window, read-only", () => {
    const read = statementsOfRole(template, "AgenticAI-PortalApi-nonprod").find((s) => s.Sid === "PortalReadRegistry")!;
    expect(JSON.stringify(read.Resource)).toContain(DISCOVERY_REGISTRY.arn);
    const functions = Object.values(template.findResources("AWS::Lambda::Function")).map(
      (f) => (f as { Properties: { Handler: string; Environment?: { Variables: Record<string, unknown> } } }).Properties,
    );
    const readFunction = functions.find((f) => f.Handler === "handler.handler")!;
    expect(readFunction.Environment!.Variables.PORTAL_DISCOVERY_REGISTRY_ID).toBe(DISCOVERY_REGISTRY.id);
    expect(readFunction.Environment!.Variables.PORTAL_OWNER_GROUPS).toBe('["travel-platform"]');
    expect(readFunction.Environment!.Variables.PORTAL_INACTIVE_DAYS).toBe("14");
  });

  it("passes cdk-nag", () => {
    expect(nagErrors(stack)).toEqual([]);
  });

  it("refuses a containment cell when governed actions are off: there would be no audit trail", () => {
    expect(
      () =>
        new AgentFactoryPortalStack(new App(), "NoActions", {
          env: { account: PLATFORM, region: REGION },
          environment: "nonprod",
          identityProvider: "cognito",
          webAclArn: WEB_ACL,
          cells: [cell({ containment: true })],
          apiCodePath: apiCode,
          webDistPath: webDist,
        }),
    ).toThrow(/containment, which needs governed actions/);
  });

  it("creates no containment function, role or route when no cell opted in", () => {
    const none = Template.fromStack(portal([cell()]));
    expect(
      Object.keys(none.findResources("AWS::IAM::Role", { Properties: { RoleName: "AgenticAI-PortalContainment-nonprod" } })),
    ).toHaveLength(0);
    const routes = Object.values(none.findResources("AWS::ApiGatewayV2::Route")).map(
      (r) => (r as { Properties: { RouteKey: string } }).Properties.RouteKey,
    );
    expect(routes.some((key) => key.includes("containment"))).toBe(false);
  });
});

describe("Phase 29 — Omni context graph read", () => {
  it("is granted only for an Omni space in the portal's own account, pinned to its Region", () => {
    const own = Template.fromStack(
      portal([cell({ accountId: PLATFORM, omniRegion: "us-west-2", omniDomainUrl: "https://example.cloudwatch-omni.global.app.aws" })]),
    );
    const statement = statementsOfRole(own, "AgenticAI-PortalApi-nonprod").find((s) => s.Sid === "PortalReadOmniContextGraph")!;
    expect(statement.Action).toBe("cloudwatch:GetContextGraph");
    expect(statement.Condition).toEqual({ StringEquals: { "aws:RequestedRegion": ["us-west-2"] } });

    const other = Template.fromStack(portal([cell({ omniRegion: "us-west-2" })]));
    expect(statementsOfRole(other, "AgenticAI-PortalApi-nonprod").some((s) => s.Sid === "PortalReadOmniContextGraph")).toBe(false);
  });

  it("rejects an Omni URL that is not https", () => {
    const app = new App({
      context: {
        "agenticai/portalEnvironment": "nonprod",
        "agenticai/portalAccountId": PLATFORM,
        "agenticai/portalWebAclArn": WEB_ACL,
        "agenticai/portalApiCodePath": apiCode,
        "agenticai/portalWebDistPath": webDist,
        "agenticai/portalCells": JSON.stringify([
          { tenantId: "ws1", agentId: "a", accountId: CELL, region: REGION, externalId: EXTERNAL_ID, omniDomainUrl: "http://insecure.example" },
        ]),
      },
    });
    expect(() => addAgentFactoryPortalStage(app, "agent-factory-portal", REGION)).toThrow(/must be an https URL/);
  });
});

describe("Phase 29 — external inventory reader", () => {
  const stack = new AgentFactoryPortalExternalReaderStack(withNag(new App()), "External", {
    env: { account: CELL, region: REGION },
    environment: "nonprod",
    trustedAccountId: EXTERNAL,
    trustedPrincipalArn: `arn:aws:iam::${EXTERNAL}:role/inventory-connector`,
    externalId: EXTERNAL_ID,
    sourceIpv4Cidrs: ["198.51.100.10/32"],
  });
  const template = Template.fromStack(stack);
  const statements = statementsOfRole(template, "AgenticAI-ExternalInventoryReader-nonprod");

  it("does not read a Runtime's configuration, which holds its environment variables", () => {
    expect(PORTAL_EXTERNAL_READER_AGENTCORE_ACTIONS).not.toContain("bedrock-agentcore:GetAgentRuntime");
    expect(actions(statements)).not.toContain("bedrock-agentcore:GetAgentRuntime");
  });

  it("reads inventory and metrics and nothing else", () => {
    expect(actions(statements).sort()).toEqual(
      [...PORTAL_EXTERNAL_READER_AGENTCORE_ACTIONS, ...PORTAL_EXTERNAL_READER_METRIC_ACTIONS].sort(),
    );
    for (const action of actions(statements)) {
      expect(action).toMatch(/:(Get|List)/);
      expect(action).not.toMatch(/Invoke|Delete|Update|Create|Put|Memory|Session|Policy/);
    }
    expect(actions(statements).some((a) => a.startsWith("bedrock:") || a.startsWith("logs:") || a.startsWith("s3:"))).toBe(false);
  });

  it("is assumed with an external id, by the named principal, from the named addresses", () => {
    template.hasResourceProperties("AWS::IAM::Role", {
      RoleName: "AgenticAI-ExternalInventoryReader-nonprod",
      AssumeRolePolicyDocument: {
        Statement: [
          Match.objectLike({
            Action: "sts:AssumeRole",
            Principal: { AWS: `arn:aws:iam::${EXTERNAL}:role/inventory-connector` },
            Condition: {
              StringEquals: { "sts:ExternalId": EXTERNAL_ID },
              IpAddress: { "aws:SourceIp": ["198.51.100.10/32"] },
            },
          }),
        ],
      },
    });
    template.resourceCountIs("AWS::IAM::AccessKey", 0);
    template.resourceCountIs("AWS::IAM::User", 0);
  });

  it("refuses a principal outside the trusted account and a malformed address", () => {
    const base = {
      env: { account: CELL, region: REGION },
      environment: "nonprod" as const,
      trustedAccountId: EXTERNAL,
      externalId: EXTERNAL_ID,
    };
    expect(
      () =>
        new AgentFactoryPortalExternalReaderStack(new App(), "BadPrincipal", {
          ...base,
          trustedPrincipalArn: `arn:aws:iam::${PLATFORM}:role/someone-else`,
        }),
    ).toThrow(/must belong to trustedAccountId/);
    expect(
      () => new AgentFactoryPortalExternalReaderStack(new App(), "BadCidr", { ...base, sourceIpv4Cidrs: ["anywhere"] }),
    ).toThrow(/not an IPv4 CIDR/);
  });

  it("passes cdk-nag", () => {
    expect(nagErrors(stack)).toEqual([]);
  });
});

describe("Phase 29 — organization discovery Registry stage", () => {
  it("turns on organization-scoped auto-detection and publishes its id and ARN", () => {
    const app = new App({ context: { "agenticai/portalAccountId": PLATFORM } });
    expect(addAgentFactoryPortalStage(app, "agent-factory-portal-discovery-registry", REGION)).toBe(true);
    const template = Template.fromStack(app.node.findChild("AgenticAI-AgentFactoryPortal-DiscoveryRegistry") as Stack);
    template.hasResourceProperties("AWS::AgentRegistry::Registry", {
      Name: "agenticai-discovery-v1",
      AutoDetectionEnabled: true,
      AutoDetectionScope: "ORGANIZATION",
    });
    template.hasResourceProperties("AWS::SSM::Parameter", { Name: "/agenticai/registry/discovery/v1/id" });
  });
});
