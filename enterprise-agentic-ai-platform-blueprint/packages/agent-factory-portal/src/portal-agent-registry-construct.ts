/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: MIT-0
 */
import { CfnResource, RemovalPolicy, Tags } from "aws-cdk-lib";
import { StringParameter } from "aws-cdk-lib/aws-ssm";
import { Construct } from "constructs";
import { PortalEnvironment } from "./naming";

export function portalAgentRegistryName(environment: PortalEnvironment): string {
  return `agenticai-agents-${environment}-v1`;
}

/** SSM parameters under which the agent Registry is published for pipelines and the portal. */
export function agentRegistrySsmParameter(environment: PortalEnvironment, leaf: "id" | "arn"): string {
  return `/agenticai/registry/agents/v1/${environment}/${leaf}`;
}

export interface PortalAgentRegistryProps {
  readonly environment: PortalEnvironment;
  /** Keep the Registry when the stack is deleted. Defaults to true. */
  readonly retain?: boolean;
}

/**
 * The Registry that holds agent governance records.
 *
 * It is separate from the Platform Registry on purpose. The Platform Registry
 * approves automatically because the Platform pipeline is the authority for
 * tool records; an agent record is decided by a person (registrar and
 * approver are different identities), so its Registry has no auto-approval
 * rule and a submitted record waits in PENDING_APPROVAL.
 *
 * Creating a Registry is a protected authority (SCP-11), so this construct is
 * deployed by operators in its own stage, never by the portal stack; the
 * portal stack receives the Registry id and ARN as context.
 */
export class PortalAgentRegistry extends Construct {
  readonly registry: CfnResource;
  readonly registryId: string;
  readonly registryArn: string;

  constructor(scope: Construct, id: string, props: PortalAgentRegistryProps) {
    super(scope, id);
    const retain = props.retain ?? true;
    this.registry = new CfnResource(this, "Registry", {
      type: "AWS::AgentRegistry::Registry",
      properties: {
        Name: portalAgentRegistryName(props.environment),
        Description: `Agent governance records (${props.environment}). Manual approval: a submitted record waits for an approver.`,
        AuthorizerType: "AWS_IAM",
      },
    });
    this.registry.applyRemovalPolicy(retain ? RemovalPolicy.RETAIN_ON_UPDATE_OR_DELETE : RemovalPolicy.DESTROY);
    Tags.of(this.registry).add("environment", props.environment);
    this.registryId = this.registry.getAtt("RegistryId").toString();
    this.registryArn = this.registry.getAtt("RegistryArn").toString();

    for (const [leaf, value] of [
      ["id", this.registryId],
      ["arn", this.registryArn],
    ] as const) {
      const parameter = new StringParameter(this, `Parameter-${leaf}`, {
        parameterName: agentRegistrySsmParameter(props.environment, leaf),
        stringValue: value,
        description: `Agent governance Registry ${leaf} (${props.environment}).`,
      });
      if (retain) parameter.applyRemovalPolicy(RemovalPolicy.RETAIN_ON_UPDATE_OR_DELETE);
    }
  }
}
