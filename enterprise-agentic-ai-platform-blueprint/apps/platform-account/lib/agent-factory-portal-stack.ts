/**
 * Agent Factory Portal — the product surface of the Agent Factory for the
 * developer experience, platform control, and assurance and operations planes
 * (README sections 1, 2.2, 7, 9 and 13.4). Opt-in: nothing else in the
 * blueprint depends on it.
 *
 * Two stacks, deployed in this order:
 *
 *   1. `agent-factory-portal-edge` stage -> AgentFactoryPortalEdgeStack in
 *      us-east-1 (CloudFront-scope web ACLs exist only there). Its
 *      `PortalWebAclArn` output is passed to the next stage as
 *      `agenticai/portalWebAclArn`.
 *   2. `agent-factory-portal` stage -> AgentFactoryPortalStack in the Platform
 *      account and Region: sign-in, the read-only API, and static hosting.
 *
 * Operating-model rules this stack keeps:
 *   - "Central visibility must not become central write access": the API role
 *     holds read actions only and reads each Workstream cell through that
 *     cell's `AgenticAI-PortalFleetReader-<env>` role.
 *   - "Pipeline-only Workstream mutation": the stack creates no resource in a
 *     Workstream account and grants no mutation there.
 *
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: MIT-0
 */
import { CfnOutput, Stack, type StackProps } from "aws-cdk-lib";
import { Key } from "aws-cdk-lib/aws-kms";
import { StringParameter } from "aws-cdk-lib/aws-ssm";
import { Construct } from "constructs";

import {
  PortalActions,
  PortalApi,
  PortalAuditTrail,
  PortalCell,
  PortalCognitoIdentity,
  PortalEdgeWebAcl,
  PortalEntraIdentityProps,
  PortalEnvironment,
  PortalIdentityProvider,
  PortalRole,
  PortalWebHosting,
  registrySsmParameter,
  resolvePortalEntraIdentity,
} from "@agenticai/agent-factory-portal";

export interface AgentFactoryPortalEdgeStackProps extends StackProps {
  readonly environment: PortalEnvironment;
  readonly allowedIpv4Cidrs: readonly string[];
  readonly allowedIpv6Cidrs?: readonly string[];
  /** Operator-provisioned key ARN (us-east-1) for the web ACL log group. */
  readonly logsKeyArn?: string;
}

export class AgentFactoryPortalEdgeStack extends Stack {
  constructor(scope: Construct, id: string, props: AgentFactoryPortalEdgeStackProps) {
    const { environment, allowedIpv4Cidrs, allowedIpv6Cidrs, logsKeyArn, ...stackProps } = props;
    super(scope, id, stackProps);
    if (this.region !== "us-east-1") {
      throw new Error("AgentFactoryPortalEdgeStack must be deployed to us-east-1.");
    }
    const acl = new PortalEdgeWebAcl(this, "Edge", {
      environment,
      allowedIpv4Cidrs,
      allowedIpv6Cidrs,
      logsKey: logsKeyArn ? Key.fromKeyArn(this, "LogsKey", logsKeyArn) : undefined,
    });
    new CfnOutput(this, "PortalWebAclArn", {
      value: acl.webAcl.attrArn,
      description: "Pass to the agent-factory-portal stage as agenticai/portalWebAclArn.",
    });
  }
}

export interface AgentFactoryPortalStackProps extends StackProps {
  readonly environment: PortalEnvironment;
  readonly identityProvider: PortalIdentityProvider;
  /** Required when identityProvider is `entra`. */
  readonly entra?: PortalEntraIdentityProps;
  /** Optional workforce SAML metadata URL when identityProvider is `cognito`. */
  readonly samlMetadataUrl?: string;
  readonly samlGroupsAttribute?: string;
  /** Extra identity-provider group or role names mapped to portal roles. */
  readonly extraGroupRoleMap?: Readonly<Record<string, PortalRole>>;
  readonly webAclArn: string;
  readonly cells: readonly PortalCell[];
  /** Built API bundle directory (`apps/agent-factory-portal/api/dist`). */
  readonly apiCodePath: string;
  /** Built web application directory (`apps/agent-factory-portal/web/dist`). */
  readonly webDistPath: string;
  readonly modelAllowlist?: readonly {
    readonly modelId: string;
    readonly provider: string;
    readonly regions: readonly string[];
    readonly status: string;
  }[];
  readonly guardrailTag?: { readonly key: string; readonly value: string };
  readonly retainData?: boolean;
  /** Operator-provisioned key ARN for the portal's log groups. */
  readonly logsKeyArn?: string;
  /**
   * Governed registration and approval (opt-in). Off by default: the portal
   * is then read-only and has no write route, role or table.
   */
  readonly governedActions?: {
    /** Group or app-role name to the tenant ids its members may register for. */
    readonly groupTenantMap: Readonly<Record<string, readonly string[]>>;
  };
  /**
   * Registry the portal reads and, with governed actions, writes agent
   * records to. Defaults to the Platform Registry of the environment
   * (`/agenticai/registry/v1/<env>/{id,arn}`).
   */
  readonly registry?: { readonly id: string; readonly arn: string };
}

export class AgentFactoryPortalStack extends Stack {
  readonly portalUrl: string;
  /** The runtime `config.json` published with the web application. */
  readonly webConfig: Record<string, unknown>;

  constructor(scope: Construct, id: string, props: AgentFactoryPortalStackProps) {
    const {
      environment,
      identityProvider,
      entra,
      samlMetadataUrl,
      samlGroupsAttribute,
      extraGroupRoleMap,
      webAclArn,
      cells,
      apiCodePath,
      webDistPath,
      modelAllowlist,
      guardrailTag,
      retainData,
      logsKeyArn,
      governedActions,
      registry,
      ...stackProps
    } = props;
    super(scope, id, stackProps);

    const web = new PortalWebHosting(this, "Web", {
      environment,
      webAclArn,
      retainBuckets: retainData,
    });
    this.portalUrl = web.origin;

    let jwtIssuer: string;
    let jwtAudience: readonly string[];
    let groupRoleMap: Record<string, PortalRole>;
    let webAuthConfig: Record<string, unknown>;
    if (identityProvider === "cognito") {
      const identity = new PortalCognitoIdentity(this, "Identity", {
        environment,
        portalOrigins: [web.origin],
        samlMetadataUrl,
        samlGroupsAttribute,
        retainUserPool: retainData,
      });
      jwtIssuer = identity.issuer;
      jwtAudience = [identity.client.userPoolClientId];
      groupRoleMap = { ...identity.groupRoleMap, ...(extraGroupRoleMap ?? {}) };
      webAuthConfig = {
        authProvider: "cognito",
        cognito: {
          authority: identity.issuer,
          clientId: identity.client.userPoolClientId,
          domain: identity.hostedUiBaseUrl,
          scopes: ["openid", "email", "profile"],
        },
      };
      new CfnOutput(this, "PortalUserPoolId", { value: identity.userPool.userPoolId });
      new CfnOutput(this, "PortalUserPoolClientId", { value: identity.client.userPoolClientId });
    } else {
      if (!entra) {
        throw new Error("AgentFactoryPortalStack: identityProvider 'entra' requires the entra settings.");
      }
      const resolved = resolvePortalEntraIdentity(entra);
      jwtIssuer = resolved.issuer;
      jwtAudience = resolved.audience;
      groupRoleMap = { ...entra.groupRoleMap, ...(extraGroupRoleMap ?? {}) };
      webAuthConfig = {
        authProvider: "entra",
        entra: {
          tenantId: entra.tenantId,
          clientId: entra.spaClientId,
          apiScope: entra.apiScope,
        },
      };
    }

    const registryId =
      registry?.id ??
      StringParameter.valueForStringParameter(this, registrySsmParameter(environment, "id"));
    const registryArn =
      registry?.arn ??
      StringParameter.valueForStringParameter(this, registrySsmParameter(environment, "arn"));
    const logsKey = logsKeyArn ? Key.fromKeyArn(this, "LogsKey", logsKeyArn) : undefined;
    const audit = governedActions
      ? new PortalAuditTrail(this, "Audit", { environment, retain: retainData })
      : undefined;

    const api = new PortalApi(this, "Api", {
      environment,
      codePath: apiCodePath,
      identityProvider,
      jwtIssuer,
      jwtAudience,
      groupRoleMap,
      registryId,
      registryArn,
      cells,
      allowedOrigins: [web.origin],
      modelAllowlist,
      guardrailTag,
      logsKey,
      auditTable: audit?.table,
    });

    if (governedActions && audit) {
      const actions = new PortalActions(this, "Actions", {
        environment,
        codePath: apiCodePath,
        httpApi: api.httpApi,
        authorizer: api.authorizer,
        registryId,
        registryArn,
        auditTable: audit.table,
        identityProvider,
        groupRoleMap,
        groupTenantMap: governedActions.groupTenantMap,
        allowedOrigins: [web.origin],
        logsKey,
      });
      new CfnOutput(this, "PortalRegistrarRoleArn", { value: actions.registrarRole.roleArn });
      new CfnOutput(this, "PortalApproverRoleArn", {
        value: actions.approverRole.roleArn,
        description:
          "Add to the protected authority manifest (purpose: registry) where SCP-11 is attached, or approvals are denied.",
      });
    }

    this.webConfig = {
      apiBaseUrl: api.apiBaseUrl,
      environment,
      features: { readOnly: !governedActions, governedActions: !!governedActions },
      ...webAuthConfig,
    };
    web.publish(webDistPath, this.webConfig);

    new CfnOutput(this, "PortalUrl", {
      value: web.origin,
      description: "Agent Factory Portal URL.",
    });
    new CfnOutput(this, "PortalApiBaseUrl", { value: api.apiBaseUrl });
    new CfnOutput(this, "PortalApiRoleArn", {
      value: api.role.roleArn,
      description: "The only principal each cell's fleet reader role trusts.",
    });
    new CfnOutput(this, "PortalDistributionId", { value: web.distribution.distributionId });
  }
}
