/**
 * Agent Factory Portal fleet reader — the one resource the portal needs in a
 * Workstream cell account: a read-only role that only the portal API role of
 * the Platform account can assume, and only with the cell's external id.
 *
 * Deployed by the `agent-factory-portal-fleet-reader` stage with the cell
 * account's own credentials or deployment role. It reads; it never changes a
 * cell ("central visibility must not become central write access").
 *
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: MIT-0
 */
import { CfnOutput, Stack, type StackProps } from "aws-cdk-lib";
import { Construct } from "constructs";

import {
  PortalContainmentTargetRole,
  PortalEnvironment,
  PortalExternalReaderRole,
  PortalFleetReaderRole,
} from "@agenticai/agent-factory-portal";

export interface AgentFactoryPortalFleetReaderStackProps extends StackProps {
  readonly environment: PortalEnvironment;
  readonly platformAccountId: string;
  readonly externalId: string;
  readonly spansLogGroupNames?: readonly string[];
}

export class AgentFactoryPortalFleetReaderStack extends Stack {
  constructor(
    scope: Construct,
    id: string,
    props: AgentFactoryPortalFleetReaderStackProps,
  ) {
    const { environment, platformAccountId, externalId, spansLogGroupNames, ...stackProps } = props;
    super(scope, id, stackProps);
    const reader = new PortalFleetReaderRole(this, "FleetReader", {
      environment,
      platformAccountId,
      externalId,
      spansLogGroupNames,
    });
    new CfnOutput(this, "PortalFleetReaderRoleArn", { value: reader.role.roleArn });
  }
}

export interface AgentFactoryPortalContainmentStackProps extends StackProps {
  readonly environment: PortalEnvironment;
  readonly platformAccountId: string;
  readonly externalId: string;
}

/**
 * Opt-in, per cell: grants the portal's containment function the authority to
 * block and unblock invocation of this cell's Runtimes and stop their
 * sessions (see PortalContainmentTargetRole). A cell that does not deploy
 * this stack cannot be contained from the portal.
 */
export class AgentFactoryPortalContainmentStack extends Stack {
  constructor(scope: Construct, id: string, props: AgentFactoryPortalContainmentStackProps) {
    const { environment, platformAccountId, externalId, ...stackProps } = props;
    super(scope, id, stackProps);
    const target = new PortalContainmentTargetRole(this, "ContainmentTarget", {
      environment,
      platformAccountId,
      externalId,
    });
    new CfnOutput(this, "PortalContainmentTargetRoleArn", { value: target.role.roleArn });
  }
}

export interface AgentFactoryPortalExternalReaderStackProps extends StackProps {
  readonly environment: PortalEnvironment;
  readonly trustedAccountId: string;
  readonly trustedPrincipalArn?: string;
  readonly externalId: string;
  readonly sourceIpv4Cidrs?: readonly string[];
}

/**
 * Opt-in, per account: a keyless, read-only inventory role for an external
 * governance tool (see PortalExternalReaderRole).
 */
export class AgentFactoryPortalExternalReaderStack extends Stack {
  constructor(scope: Construct, id: string, props: AgentFactoryPortalExternalReaderStackProps) {
    const { environment, trustedAccountId, trustedPrincipalArn, externalId, sourceIpv4Cidrs, ...stackProps } = props;
    super(scope, id, stackProps);
    const reader = new PortalExternalReaderRole(this, "ExternalReader", {
      environment,
      trustedAccountId,
      trustedPrincipalArn,
      externalId,
      sourceIpv4Cidrs,
    });
    new CfnOutput(this, "ExternalInventoryReaderRoleArn", { value: reader.role.roleArn });
  }
}
