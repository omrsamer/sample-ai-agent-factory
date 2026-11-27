/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: MIT-0
 */
import { CfnResource, RemovalPolicy, Validations } from "aws-cdk-lib";
import { StringParameter } from "aws-cdk-lib/aws-ssm";
import { Construct } from "constructs";

export const PORTAL_DISCOVERY_REGISTRY_NAME = "agenticai-discovery-v1";

/** SSM parameters under which the discovery Registry is published. */
export function discoveryRegistrySsmParameter(leaf: "id" | "arn"): string {
  return `/agenticai/registry/discovery/v1/${leaf}`;
}

export interface PortalDiscoveryRegistryProps {
  /** Keep the Registry when the stack is deleted. Defaults to true. */
  readonly retain?: boolean;
}

/**
 * The organization-scoped discovery Registry: AWS Agent Registry detects every
 * AgentCore Runtime and Gateway of the organization's accounts and keeps one
 * record per resource, with its source ARN, in sync on create, update and
 * delete. No role is needed in the member accounts.
 *
 * It answers a different question from the other two Registries. The Platform
 * Registry says which tools are approved; the agent Registry says which agents
 * a person has registered and approved; this one says what actually exists.
 * The portal joins it with the agent Registry on the Runtime ARN, so an agent
 * is registered and detected, detected only (unmanaged), or registered only.
 *
 * Prerequisites, set once by operators in the management account: trusted
 * access for `agent-registry.amazonaws.com` and this account registered as the
 * delegated administrator for it. An organization has one such Registry per
 * Region. Deployed by operators in its own stage (creating a Registry is a
 * protected authority).
 */
export class PortalDiscoveryRegistry extends Construct {
  readonly registry: CfnResource;
  readonly registryId: string;
  readonly registryArn: string;

  constructor(scope: Construct, id: string, props: PortalDiscoveryRegistryProps = {}) {
    super(scope, id);
    const retain = props.retain ?? true;
    this.registry = new CfnResource(this, "Registry", {
      type: "AWS::AgentRegistry::Registry",
      properties: {
        Name: PORTAL_DISCOVERY_REGISTRY_NAME,
        Description:
          "Organization-scoped discovery of AgentCore Runtimes and Gateways. Records are created and kept in sync by AWS Agent Registry.",
        AuthorizerType: "AWS_IAM",
        AutoDetectionEnabled: true,
        AutoDetectionScope: "ORGANIZATION",
      },
    });
    this.registry.applyRemovalPolicy(retain ? RemovalPolicy.RETAIN_ON_UPDATE_OR_DELETE : RemovalPolicy.DESTROY);
    // The resource schema bundled with this aws-cdk-lib predates the two
    // auto-detection properties; the CloudFormation registry type has them
    // (deployed and verified: the Registry reports autoDetection ACTIVE).
    Validations.of(this.registry).acknowledge({
      id: "CloudFormation-Validate::F3002",
      reason:
        "AutoDetectionEnabled and AutoDetectionScope are properties of the live AWS::AgentRegistry::Registry type; the schema bundled with aws-cdk-lib is older.",
    });
    this.registryId = this.registry.getAtt("RegistryId").toString();
    this.registryArn = this.registry.getAtt("RegistryArn").toString();
    for (const [leaf, value] of [
      ["id", this.registryId],
      ["arn", this.registryArn],
    ] as const) {
      const parameter = new StringParameter(this, `Parameter-${leaf}`, {
        parameterName: discoveryRegistrySsmParameter(leaf),
        stringValue: value,
        description: `Organization discovery Registry ${leaf}.`,
      });
      if (retain) parameter.applyRemovalPolicy(RemovalPolicy.RETAIN_ON_UPDATE_OR_DELETE);
    }
  }
}
