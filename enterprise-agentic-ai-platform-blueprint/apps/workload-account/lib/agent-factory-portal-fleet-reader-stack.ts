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
  PortalEnvironment,
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
