/**
 * Stage routing for the Agent Factory Portal. Kept out of
 * `bin/agentic-ai-platform.ts` so the entry point only names the stages.
 *
 *   agent-factory-portal-edge          us-east-1 web ACL (Platform account)
 *   agent-factory-portal               sign-in, API and hosting (Platform account)
 *   agent-factory-portal-fleet-reader  read-only role (each Workstream cell account)
 *
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: MIT-0
 */
import * as fs from "fs";
import * as path from "path";
import { App, Tags } from "aws-cdk-lib";

import {
  PORTAL_ROLES,
  PortalCell,
  PortalEntraIdentityProps,
  PortalEnvironment,
  PortalRole,
  isPortalEnvironment,
  portalEdgeStackName,
  portalFleetReaderStackName,
  portalStackName,
} from "@agenticai/agent-factory-portal";
import {
  AgentFactoryPortalAgentRegistryStack,
  AgentFactoryPortalEdgeStack,
  AgentFactoryPortalStack,
} from "./agent-factory-portal-stack";
import { AgentFactoryPortalFleetReaderStack } from "../../workload-account/lib/agent-factory-portal-fleet-reader-stack";

export const AGENT_FACTORY_PORTAL_STAGES = [
  "agent-factory-portal-agent-registry",
  "agent-factory-portal-edge",
  "agent-factory-portal",
  "agent-factory-portal-fleet-reader",
] as const;

const BLUEPRINT_ROOT = path.resolve(__dirname, "..", "..", "..");

function context(app: App, key: string): unknown {
  return app.node.tryGetContext(key);
}

function requireAccount(app: App, key: string, stage: string): string {
  const value = context(app, key);
  if (typeof value !== "string" || !/^\d{12}$/.test(value)) {
    throw new Error(`${stage} stage requires context '${key}' (12 digits).`);
  }
  return value;
}

function requireEnvironment(app: App, stage: string): PortalEnvironment {
  const value = context(app, "agenticai/portalEnvironment");
  if (!isPortalEnvironment(value)) {
    throw new Error(`${stage} stage requires context 'agenticai/portalEnvironment' (nonprod or prod).`);
  }
  return value;
}

function jsonContext<T>(app: App, key: string): T | undefined {
  const raw = context(app, key);
  if (raw === undefined) return undefined;
  if (typeof raw !== "string") return raw as T;
  try {
    return JSON.parse(raw) as T;
  } catch {
    throw new Error(`Context ${key} must be valid JSON.`);
  }
}

function listContext(app: App, key: string): string[] {
  const raw = context(app, key);
  if (raw === undefined) return [];
  if (Array.isArray(raw)) return raw.map(String);
  const text = String(raw).trim();
  if (text.startsWith("[")) return (JSON.parse(text) as unknown[]).map(String);
  return text.split(",").map((v) => v.trim()).filter(Boolean);
}

function keyArnContext(app: App, key: string, region: string): string | undefined {
  const value = context(app, key);
  if (value === undefined) return undefined;
  if (typeof value !== "string" || !new RegExp(`^arn:aws[\\w-]*:kms:${region}:\\d{12}:key/[0-9a-f-]{36}$`).test(value)) {
    throw new Error(`Context ${key} must be a KMS key ARN in ${region}.`);
  }
  return value;
}

function governedActionsContext(
  app: App,
): { groupTenantMap: Record<string, string[]> } | undefined {
  const enabled = context(app, "agenticai/portalGovernedActions");
  if (enabled !== true && enabled !== "true") return undefined;
  const map = jsonContext<Record<string, unknown>>(app, "agenticai/portalGroupTenantMap") ?? {};
  const groupTenantMap: Record<string, string[]> = {};
  for (const [group, tenants] of Object.entries(map)) {
    if (!Array.isArray(tenants) || tenants.some((t) => typeof t !== "string" || t.length === 0)) {
      throw new Error(
        `Context agenticai/portalGroupTenantMap: '${group}' must map to a list of tenant ids.`,
      );
    }
    groupTenantMap[group] = tenants as string[];
  }
  return { groupTenantMap };
}

function registryContext(
  app: App,
  region: string,
  idKey = "agenticai/portalRegistryId",
  arnKey = "agenticai/portalRegistryArn",
): { id: string; arn: string } | undefined {
  const id = context(app, idKey);
  const arn = context(app, arnKey);
  if (id === undefined && arn === undefined) return undefined;
  if (typeof id !== "string" || !/^[A-Za-z0-9]{16}$/.test(id)) {
    throw new Error(`Context ${idKey} must be a 16-character Registry id.`);
  }
  const expected = new RegExp(`^arn:aws[\\w-]*:agent-registry:${region}:\\d{12}:registry/${id}$`);
  if (typeof arn !== "string" || !expected.test(arn)) {
    throw new Error(
      `Context ${arnKey} must be the ARN of the Registry named by ${idKey}, in the portal Region.`,
    );
  }
  return { id, arn };
}

function portalTags(environment: PortalEnvironment): Record<string, string> {
  return {
    "application-id": "agent-factory-portal",
    "agent-id": "shared",
    "tenant-id": "shared",
    "cost-centre": "platform",
    environment,
  };
}

function applyTags(scope: AgentFactoryPortalStack | AgentFactoryPortalEdgeStack | AgentFactoryPortalFleetReaderStack, environment: PortalEnvironment): void {
  for (const [key, value] of Object.entries(portalTags(environment))) {
    Tags.of(scope).add(key, value);
  }
}

function roleMapContext(app: App, key: string): Record<string, PortalRole> | undefined {
  const map = jsonContext<Record<string, string>>(app, key);
  if (map === undefined) return undefined;
  for (const [group, role] of Object.entries(map)) {
    if (!(PORTAL_ROLES as readonly string[]).includes(role)) {
      throw new Error(
        `Context ${key}: '${group}' maps to '${role}', which is not a portal role (${PORTAL_ROLES.join(", ")}).`,
      );
    }
  }
  return map as Record<string, PortalRole>;
}

function cellsContext(app: App, environment: PortalEnvironment): PortalCell[] {
  const cells = jsonContext<Record<string, unknown>[]>(app, "agenticai/portalCells") ?? [];
  if (!Array.isArray(cells)) {
    throw new Error("Context agenticai/portalCells must be a JSON array.");
  }
  return cells.map((cell, index) => {
    const text = (field: string, required: boolean): string | undefined => {
      const value = cell[field];
      if (value === undefined || value === null || value === "") {
        if (required) throw new Error(`agenticai/portalCells[${index}].${field} is required.`);
        return undefined;
      }
      return String(value);
    };
    const cellEnvironment = text("environment", false) ?? environment;
    if (!isPortalEnvironment(cellEnvironment)) {
      throw new Error(`agenticai/portalCells[${index}].environment must be nonprod or prod.`);
    }
    return {
      tenantId: text("tenantId", true)!,
      agentId: text("agentId", true)!,
      applicationId: text("applicationId", false),
      environment: cellEnvironment,
      accountId: text("accountId", true)!,
      region: text("region", true)!,
      externalId: text("externalId", true)!,
      alarmNamePrefix: text("alarmNamePrefix", false),
      pipelineName: text("pipelineName", false),
    };
  });
}

function builtAsset(app: App, key: string, fallback: string, what: string, marker: string): string {
  const configured = context(app, key);
  const directory = path.resolve(
    typeof configured === "string" && configured.length > 0 ? configured : fallback,
  );
  if (!fs.existsSync(path.join(directory, marker))) {
    throw new Error(
      `agent-factory-portal stage: ${what} not found at ${directory} (expected ${marker}). ` +
        `Build it first (see apps/agent-factory-portal/README.md) or pass -c ${key}=<directory>.`,
    );
  }
  return directory;
}

/**
 * Create the stack for a portal stage. Returns false when `stage` is not one
 * of {@link AGENT_FACTORY_PORTAL_STAGES}.
 */
export function addAgentFactoryPortalStage(
  app: App,
  stage: string,
  deploymentRegion: string,
): boolean {
  switch (stage) {
    case "agent-factory-portal-agent-registry": {
      const environment = requireEnvironment(app, stage);
      const account = requireAccount(app, "agenticai/portalAccountId", stage);
      const retain = context(app, "agenticai/portalRetainData");
      const stack = new AgentFactoryPortalAgentRegistryStack(
        app,
        `AgenticAI-AgentFactoryPortal-AgentRegistry-${environment}`,
        {
          env: { account, region: deploymentRegion },
          environment,
          retain: retain === undefined ? undefined : retain === true || retain === "true",
          description: `Agent Factory Portal (${environment}) agent governance Registry (manual approval).`,
        },
      );
      for (const [key, value] of Object.entries(portalTags(environment))) Tags.of(stack).add(key, value);
      return true;
    }
    case "agent-factory-portal-edge": {
      const environment = requireEnvironment(app, stage);
      const account = requireAccount(app, "agenticai/portalAccountId", stage);
      const v4 = listContext(app, "agenticai/portalAllowedCidrs");
      const v6 = listContext(app, "agenticai/portalAllowedIpv6Cidrs");
      const exposure = context(app, "agenticai/portalExposure") ?? "allow-list";
      if (exposure !== "allow-list" && exposure !== "public") {
        throw new Error("Context agenticai/portalExposure must be 'allow-list' or 'public'.");
      }
      if (exposure === "allow-list" && v4.length + v6.length === 0) {
        throw new Error(
          "agent-factory-portal-edge stage requires 'agenticai/portalAllowedCidrs' (or portalAllowedIpv6Cidrs). " +
            "Set agenticai/portalExposure=public only when the portal must be reachable from any address.",
        );
      }
      const stack = new AgentFactoryPortalEdgeStack(app, portalEdgeStackName(environment), {
        env: { account, region: "us-east-1" },
        environment,
        allowedIpv4Cidrs: exposure === "public" ? [] : v4,
        allowedIpv6Cidrs: exposure === "public" ? [] : v6,
        logsKeyArn: keyArnContext(app, "agenticai/portalEdgeLogsKeyArn", "us-east-1"),
        description: `Agent Factory Portal (${environment}) edge web ACL.`,
      });
      applyTags(stack, environment);
      return true;
    }
    case "agent-factory-portal": {
      const environment = requireEnvironment(app, stage);
      const account = requireAccount(app, "agenticai/portalAccountId", stage);
      const webAclArn = context(app, "agenticai/portalWebAclArn");
      if (typeof webAclArn !== "string") {
        throw new Error(
          "agent-factory-portal stage requires context 'agenticai/portalWebAclArn' (output of the agent-factory-portal-edge stage).",
        );
      }
      const identityProvider = context(app, "agenticai/portalIdentityProvider") ?? "cognito";
      if (identityProvider !== "cognito" && identityProvider !== "entra") {
        throw new Error("Context agenticai/portalIdentityProvider must be 'cognito' or 'entra'.");
      }
      let entra: PortalEntraIdentityProps | undefined;
      if (identityProvider === "entra") {
        const raw = jsonContext<Record<string, string>>(app, "agenticai/portalEntra");
        const groupRoleMap = roleMapContext(app, "agenticai/portalGroupRoleMap");
        if (!raw || !groupRoleMap) {
          throw new Error(
            "identityProvider 'entra' requires context 'agenticai/portalEntra' ({tenantId, spaClientId, apiAudience, apiScope}) and 'agenticai/portalGroupRoleMap'.",
          );
        }
        entra = {
          tenantId: String(raw.tenantId ?? ""),
          spaClientId: String(raw.spaClientId ?? ""),
          apiAudience: String(raw.apiAudience ?? ""),
          apiScope: String(raw.apiScope ?? ""),
          groupRoleMap,
        };
      }
      const samlMetadataUrl = context(app, "agenticai/portalSamlMetadataUrl");
      const samlGroupsAttribute = context(app, "agenticai/portalSamlGroupsAttribute");
      const retain = context(app, "agenticai/portalRetainData");
      const stack = new AgentFactoryPortalStack(app, portalStackName(environment), {
        env: { account, region: deploymentRegion },
        environment,
        identityProvider,
        entra,
        samlMetadataUrl: typeof samlMetadataUrl === "string" ? samlMetadataUrl : undefined,
        samlGroupsAttribute:
          typeof samlGroupsAttribute === "string" ? samlGroupsAttribute : undefined,
        extraGroupRoleMap:
          identityProvider === "cognito"
            ? roleMapContext(app, "agenticai/portalGroupRoleMap")
            : undefined,
        webAclArn,
        cells: cellsContext(app, environment),
        apiCodePath: builtAsset(
          app,
          "agenticai/portalApiCodePath",
          path.join(BLUEPRINT_ROOT, "apps", "agent-factory-portal", "api", "dist"),
          "the built portal API",
          "handler.py",
        ),
        webDistPath: builtAsset(
          app,
          "agenticai/portalWebDistPath",
          path.join(BLUEPRINT_ROOT, "apps", "agent-factory-portal", "web", "dist"),
          "the built portal web application",
          "index.html",
        ),
        modelAllowlist: jsonContext(app, "agenticai/portalModelAllowlist"),
        guardrailTag: jsonContext(app, "agenticai/portalGuardrailTag"),
        retainData: retain === undefined ? undefined : retain === true || retain === "true",
        logsKeyArn: keyArnContext(app, "agenticai/portalLogsKeyArn", deploymentRegion),
        governedActions: governedActionsContext(app),
        registry: registryContext(app, deploymentRegion),
        agentRegistry: registryContext(
          app,
          deploymentRegion,
          "agenticai/portalAgentRegistryId",
          "agenticai/portalAgentRegistryArn",
        ),
        description: `Agent Factory Portal (${environment}): sign-in, read-only API and web hosting.`,
      });
      applyTags(stack, environment);
      return true;
    }
    case "agent-factory-portal-fleet-reader": {
      const environment = requireEnvironment(app, stage);
      const cellAccount = requireAccount(app, "agenticai/portalCellAccountId", stage);
      const platformAccount = requireAccount(app, "agenticai/portalAccountId", stage);
      const externalId = context(app, "agenticai/portalExternalId");
      if (typeof externalId !== "string") {
        throw new Error(
          "agent-factory-portal-fleet-reader stage requires context 'agenticai/portalExternalId'.",
        );
      }
      const logGroups = listContext(app, "agenticai/portalSpansLogGroupNames");
      const stack = new AgentFactoryPortalFleetReaderStack(
        app,
        portalFleetReaderStackName(environment),
        {
          env: { account: cellAccount, region: deploymentRegion },
          environment,
          platformAccountId: platformAccount,
          externalId,
          spansLogGroupNames: logGroups.length > 0 ? logGroups : undefined,
          description: `Agent Factory Portal (${environment}) read-only fleet reader role.`,
        },
      );
      applyTags(stack, environment);
      return true;
    }
    default:
      return false;
  }
}
