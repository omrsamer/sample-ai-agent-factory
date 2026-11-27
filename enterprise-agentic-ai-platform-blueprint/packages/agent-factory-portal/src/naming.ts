/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: MIT-0
 */

/** Platform environments the portal can be deployed for. */
export type PortalEnvironment = "nonprod" | "prod";

/** Identity providers the portal can sign users in with. */
export type PortalIdentityProvider = "cognito" | "entra";

/**
 * Portal personas, from the blueprint operating model (README section 1.3).
 * The API maps identity-provider groups onto these roles; the web application
 * only displays them.
 */
export const PORTAL_ROLES = [
  "platform",
  "security",
  "sre",
  "finops",
  "approver",
  "developer",
  "readonly",
] as const;
export type PortalRole = (typeof PORTAL_ROLES)[number];

/** Amazon Cognito groups created for the personas, and the role each maps to. */
export const PORTAL_COGNITO_GROUPS: Readonly<Record<string, PortalRole>> = {
  "platform-engineering": "platform",
  "security-and-risk": "security",
  "platform-sre": "sre",
  finops: "finops",
  "human-approvers": "approver",
  "product-teams": "developer",
  "portal-readonly": "readonly",
};

export function isPortalEnvironment(value: unknown): value is PortalEnvironment {
  return value === "nonprod" || value === "prod";
}

export function portalStackName(environment: PortalEnvironment): string {
  return `AgenticAI-AgentFactoryPortal-${environment}`;
}

export function portalEdgeStackName(environment: PortalEnvironment): string {
  return `AgenticAI-AgentFactoryPortal-Edge-${environment}`;
}

export function portalFleetReaderStackName(environment: PortalEnvironment): string {
  return `AgenticAI-AgentFactoryPortal-FleetReader-${environment}`;
}

/** Execution role of the portal API function (Platform account). */
export function portalApiRoleName(environment: PortalEnvironment): string {
  return `AgenticAI-PortalApi-${environment}`;
}

/** Read-only role the portal API assumes in a Workstream cell account. */
export function portalFleetReaderRoleName(environment: PortalEnvironment): string {
  return `AgenticAI-PortalFleetReader-${environment}`;
}

export function portalApiRoleArn(
  partition: string,
  platformAccountId: string,
  environment: PortalEnvironment,
): string {
  return `arn:${partition}:iam::${platformAccountId}:role/${portalApiRoleName(environment)}`;
}

/** SSM parameters the Platform Registry stack already publishes. */
export function registrySsmParameter(
  environment: PortalEnvironment,
  leaf: "id" | "arn",
): string {
  return `/agenticai/registry/v1/${environment}/${leaf}`;
}

/** Role of the portal's containment function (Platform account). */
export function portalContainmentRoleName(environment: PortalEnvironment): string {
  return `AgenticAI-PortalContainment-${environment}`;
}

/** Role the containment function assumes in a Workstream cell account. */
export function portalContainmentTargetRoleName(environment: PortalEnvironment): string {
  return `AgenticAI-PortalContainmentTarget-${environment}`;
}

/** Read-only role for an external governance or inventory tool. */
export function portalExternalReaderRoleName(environment: PortalEnvironment): string {
  return `AgenticAI-ExternalInventoryReader-${environment}`;
}
