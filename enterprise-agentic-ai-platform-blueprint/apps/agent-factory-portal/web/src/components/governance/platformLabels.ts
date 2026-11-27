// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import type { IdentityStatus, Platform } from '../../api/client';

/**
 * Display labels for the hosting platform key on an agent record. Workstream cells in this
 * blueprint run on Amazon Bedrock AgentCore; any other key is shown as recorded.
 */
const PLATFORM_LABEL: Record<string, { full: string; host: string }> = {
  aws_bedrock: { full: 'Amazon Bedrock AgentCore', host: 'AWS' },
  on_prem: { full: 'On premises', host: 'On premises' },
  other: { full: 'Other', host: 'Other' },
};

function known(p: string): boolean {
  return Object.prototype.hasOwnProperty.call(PLATFORM_LABEL, p);
}

export function platformLabel(p?: Platform | null): string {
  if (!p) return '—';
  return known(p) ? PLATFORM_LABEL[p].full : p;
}

export function platformLabelOr(p: Platform | null | undefined, fallback: string): string {
  return p ? platformLabel(p) : fallback;
}

/** Short host tag for a graph node; empty when the platform is not recorded. */
export function platformHostLabel(platform: string): string {
  if (!platform) return '';
  return known(platform) ? PLATFORM_LABEL[platform].host : platform;
}

export function mcpHostLabel(kind: string): string {
  if (kind === 'gateway' || kind === 'runtime') return 'AWS';
  if (kind === 'standard') return 'External';
  return '';
}

export interface RuntimeHandleField {
  label: string;
  value: string;
  copyLabel: string;
}

/** The identifier that locates the agent's runtime, labelled for what it is. */
export function runtimeHandleField(agent: {
  agent_arn?: string | null;
  runtime_handle?: string | null;
}): RuntimeHandleField | null {
  if (agent.agent_arn) return { label: 'Runtime ARN', value: agent.agent_arn, copyLabel: 'runtime ARN' };
  if (agent.runtime_handle) {
    return { label: 'Runtime handle', value: agent.runtime_handle, copyLabel: 'runtime handle' };
  }
  return null;
}

const IDENTITY_STATUS_LABEL: Record<IdentityStatus, string> = {
  none: 'No workload identity',
  pending: 'Provisioning',
  provisioned: 'Provisioned',
  failed: 'Provisioning failed',
};

export function identityStatusLabel(status: string | undefined): string {
  return status && Object.prototype.hasOwnProperty.call(IDENTITY_STATUS_LABEL, status)
    ? IDENTITY_STATUS_LABEL[status as IdentityStatus]
    : 'Unknown';
}
