// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import type { McpServer } from '../../api/client';
import { lifecycleBadge } from './agentUi';
import { enforcementLabel } from './cedarPosture';
import { NO_READER_CHIP, NO_READER_TITLE, accountLabel, detectionSourceLabel, type Tag } from './inventory';

/**
 * Pure view rules for tool gateways, and in particular for one that no reader read.
 *
 * The organization registry detects tool gateways as well as runtimes. A gateway that a cell
 * reader read is shown in full. One that only the registry detected is listed with what the
 * detection says (its ARN, account, Region, authorizer and protocol) and nothing more: its
 * tools, its tenant, its policy engine and its policies are not known, and none of them is
 * ever shown as "none".
 */

export type GatewayReader = 'ok' | 'none' | 'unreachable' | 'not_listed' | 'unread';

type ReaderFacts = Pick<McpServer, 'reader_status'> | null | undefined;

/**
 * Whether a reader read the gateway. An API that does not send the field lists only gateways a
 * reader read. A status this build does not know is not "read": it is shown as not read.
 */
export function gatewayReader(gateway: ReaderFacts): GatewayReader {
  const raw = (gateway?.reader_status ?? '').trim().toLowerCase();
  if (raw === '' || raw === 'ok') return 'ok';
  if (raw === 'none' || raw === 'unreachable' || raw === 'not_listed') return raw;
  return 'unread';
}

export function gatewayRead(gateway: ReaderFacts): boolean {
  return gatewayReader(gateway) === 'ok';
}

const CANNOT = 'so its tools, its policy engine and its policies cannot be shown';

const NOT_READ: Record<Exclude<GatewayReader, 'ok'>, { title: string; sentence: string }> = {
  none: { title: NO_READER_TITLE, sentence: `The portal has no role in this gateway’s account, ${CANNOT}.` },
  unreachable: {
    title: 'Reader role unreachable',
    sentence: `The reader role in this gateway’s account could not be used just now, ${CANNOT}.`,
  },
  not_listed: {
    title: 'Not listed by the reader',
    sentence: `The reader role in this gateway’s account did not list this gateway, ${CANNOT}. It may have been deleted since the organization registry detected it.`,
  },
  unread: { title: 'Not read', sentence: `No reader read this gateway, ${CANNOT}.` },
};

/**
 * For a gateway no reader read: a short title and the reason as a sentence, which is the API's
 * own when it sent one. Null for a gateway a reader read.
 */
export function gatewayNotRead(gateway: Pick<McpServer, 'reader_status' | 'detail'> | null | undefined): { title: string; sentence: string } | null {
  const reader = gatewayReader(gateway);
  if (reader === 'ok') return null;
  return { title: NOT_READ[reader].title, sentence: (gateway?.detail ?? '').trim() || NOT_READ[reader].sentence };
}

/** The chip that marks a gateway no reader read, in the same style as an agent's. Null when one did. */
export function gatewayChip(gateway: Pick<McpServer, 'reader_status' | 'detail'> | null | undefined): Tag | null {
  const not = gatewayNotRead(gateway);
  return not ? { label: not.title, cls: NO_READER_CHIP.cls, hint: not.sentence } : null;
}

export const NOT_READABLE = 'Not readable';

/** The Tools cell of the list: how many, or that they cannot be read. Never "0" for a gateway no reader read. */
export function toolsCell(gateway: Pick<McpServer, 'reader_status' | 'available_tools'>): string {
  return gatewayRead(gateway) ? String(gateway.available_tools?.length ?? 0) : NOT_READABLE;
}

/** The policy cell of the list and the Overview. An unknown mode is never worded as "no policy engine". */
export function policyCell(gateway: Pick<McpServer, 'reader_status' | 'cedar_enforcement_mode'>): string {
  return gatewayRead(gateway) ? enforcementLabel(gateway.cedar_enforcement_mode) : NOT_READABLE;
}

const DETECTED_CLS = 'bg-sky-50 text-sky-700';

/**
 * The state of a gateway. One in an account where the portal has no reader role is "Not managed
 * here": the organization registry detected it and this portal reads nothing of it. One that a
 * reader could not read for another reason is "Detected only". The agents' wording
 * ("Discovered, not registered") does not apply, because a gateway is not registered through
 * the portal.
 */
export function gatewayLifecycle(gateway: Pick<McpServer, 'reader_status' | 'lifecycle_state'>): { cls: string; label: string } {
  const reader = gatewayReader(gateway);
  if (reader === 'none') return { cls: DETECTED_CLS, label: 'Not managed here' };
  if (reader !== 'ok' || gateway.lifecycle_state === 'discovered') return { cls: DETECTED_CLS, label: 'Detected only' };
  return lifecycleBadge(gateway.lifecycle_state);
}

/** The gateway's account: its alias, else its id masked to the last four digits. Never the full id. */
export function gatewayAccount(gateway: Pick<McpServer, 'account_alias' | 'account_id' | 'gateway_arn'>): string {
  return accountLabel({ account_alias: gateway.account_alias, account_id: gateway.account_id, agent_arn: gateway.gateway_arn });
}

/** What detected the gateway, in words, or an empty string when the API does not say. */
export function gatewayDetectedBy(gateway: Pick<McpServer, 'detection_sources'>): string {
  return (gateway.detection_sources ?? []).filter(Boolean).map(detectionSourceLabel).join(', ');
}

/**
 * A time the API knows, or null. Where it cannot know a time (a gateway that is only detected,
 * with no time in the detection) it sends the epoch, which must not be shown as a date.
 */
export function knownTime(iso: string | null | undefined): string | null {
  if (!iso) return null;
  const at = new Date(iso).getTime();
  return Number.isNaN(at) || at <= 0 ? null : iso;
}

/** One sentence above the list when some gateways are known from the organization registry only. Null when none is. */
export function unreadNote(count: number): string | null {
  if (!Number.isFinite(count) || count <= 0) return null;
  return count === 1
    ? '1 gateway is listed from the organization registry only: no reader role read it, so its tools and policies cannot be shown.'
    : `${count} gateways are listed from the organization registry only: no reader role read them, so their tools and policies cannot be shown.`;
}

export type ReaderFilter = 'all' | 'read' | 'unread';

export const READER_FILTER_OPTIONS: { value: ReaderFilter; label: string }[] = [
  { value: 'all', label: 'All gateways' },
  { value: 'read', label: 'Read by a reader' },
  { value: 'unread', label: 'No reader read it' },
];

/** The rows the list keeps for a search text (name or account) and the reader filter. */
export function matchesGateway(
  gateway: Pick<McpServer, 'name' | 'reader_status' | 'account_alias' | 'account_id' | 'gateway_arn'>,
  search: string,
  reader: ReaderFilter,
): boolean {
  if (reader === 'read' && !gatewayRead(gateway)) return false;
  if (reader === 'unread' && gatewayRead(gateway)) return false;
  const q = search.trim().toLowerCase();
  return !q || `${gateway.name} ${gatewayAccount(gateway)}`.toLowerCase().includes(q);
}

/** What the Connected agents panel adds for a gateway no reader read. */
export const CONNECTED_NOT_KNOWN =
  'Which agents are connected to it is therefore not shown here. An agent whose registration names this gateway lists it under its own Tool subscriptions.';
