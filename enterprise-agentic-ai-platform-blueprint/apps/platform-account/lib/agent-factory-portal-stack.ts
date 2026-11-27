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
import { StringParameter } from "aws-cdk-lib/aws-ssm";
import { Construct } from "constructs";

import {
  PortalApi,
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
}

export class AgentFactoryPortalEdgeStack extends Stack {
  constructor(scope: Construct, id: string, props: AgentFactoryPortalEdgeStackProps) {
    const { environment, allowedIpv4Cidrs, allowedIpv6Cidrs, ...stackProps } = props;
    super(scope, id, stackProps);
    if (this.region !== "us-east-1") {
      throw new Error("AgentFactoryPortalEdgeStack must be deployed to us-east-1.");
    }
    const acl = new PortalEdgeWebAcl(this, "Edge", {
      environment,
      allowedIpv4Cidrs,
      allowedIpv6Cidrs,
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
}

export class AgentFactoryPortalStack extends Stack {
  readonly portalUrl: string;

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

    const registryId = StringParameter.valueForStringParameter(
      this,
      registrySsmParameter(environment, "id"),
    );
    const registryArn = StringParameter.valueForStringParameter(
      this,
      registrySsmParameter(environment, "arn"),
    );

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
    });

    web.publish(webDistPath, {
      apiBaseUrl: api.apiBaseUrl,
      environment,
      features: { readOnly: true },
      ...webAuthConfig,
    });

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
