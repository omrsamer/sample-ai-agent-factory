// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import type { Agent, AgentFlags, RiskLevel } from '../../api/client';
import { arnAccount, maskAccountId, maskAccountIds } from '../shared/arnDisplay';
import { downloadFilename } from '../shared/download';

/**
 * Pure view rules for the inventory: how an agent's state, flags and risk are worded, and how
 * the agents list is filtered. Every label is text; colour only supports it.
 */

export interface Tag {
  label: string;
  cls: string;
  hint?: string;
}

const INVENTORY_STATE: Record<string, Tag> = {
  registered_and_detected: { label: 'Registered', cls: 'bg-emerald-50 text-emerald-800', hint: 'Registered and running.' },
  detected_only: { label: 'Not registered', cls: 'bg-red-50 text-red-800', hint: 'A runtime is running that nobody registered.' },
  registered_only: { label: 'Registered, not running', cls: 'bg-slate-100 text-slate-700', hint: 'Registered, but no runtime was detected.' },
};

export const INVENTORY_STATE_OPTIONS: { value: string; label: string }[] = Object.entries(INVENTORY_STATE).map(
  ([value, tag]) => ({ value, label: tag.label }),
);

/** Tag for an inventory state. Absent is "Unknown"; an unrecognised value is shown as recorded. */
export function inventoryStateTag(state: string | null | undefined): Tag {
  if (!state) return { label: 'State unknown', cls: 'bg-slate-100 text-slate-700' };
  return Object.prototype.hasOwnProperty.call(INVENTORY_STATE, state)
    ? INVENTORY_STATE[state]
    : { label: state, cls: 'bg-slate-100 text-slate-700' };
}

const DETECTION_SOURCE: Record<string, string> = {
  cell_reader: 'Cell reader',
  organization_registry: 'Organization registry',
};

/** Where an agent's runtime was seen, in words. An unrecognised source is shown as recorded. */
export function detectionSourceLabel(source: string): string {
  return Object.prototype.hasOwnProperty.call(DETECTION_SOURCE, source) ? DETECTION_SOURCE[source] : source;
}

export type FlagName = keyof AgentFlags;

export const FLAG_NAMES: readonly FlagName[] = ['contained', 'unmanaged', 'ownerless', 'review_overdue', 'inactive'];

const FLAG_VIEW: Record<FlagName, { label: string; cls: string; hint: string; unknown: string }> = {
  contained: {
    label: 'Contained',
    cls: 'bg-red-700 text-white',
    hint: 'New invocations are denied until the agent is released.',
    unknown: 'Containment unknown',
  },
  // Never a chip of its own: the state tag and the lifecycle say it. It is a filter and a count.
  unmanaged: { label: 'No approved registration', cls: 'bg-red-50 text-red-800', hint: 'The agent has no approved registration.', unknown: 'Registration unknown' },
  ownerless: {
    label: 'Ownerless',
    cls: 'bg-amber-50 text-amber-900',
    hint: 'No owner group, or one that is not in the owner roster.',
    unknown: 'Ownership unknown',
  },
  review_overdue: { label: 'Review overdue', cls: 'bg-amber-50 text-amber-900', hint: 'The review date has passed.', unknown: 'Review state unknown' },
  inactive: { label: 'Inactive', cls: 'bg-slate-100 text-slate-700', hint: 'No invocation in the inactivity window.', unknown: 'Activity unknown' },
};

export function flagLabel(name: string): string {
  return Object.prototype.hasOwnProperty.call(FLAG_VIEW, name) ? FLAG_VIEW[name as FlagName].label : name;
}

export function flagHint(name: FlagName): string {
  return FLAG_VIEW[name].hint;
}

export type FlagState = 'set' | 'clear' | 'unknown';

/**
 * Reads one flag. Only the boolean `true` is set and only `false` is clear; `null`, a missing
 * flag and a missing flags object are all unknown, and are never read as false.
 */
export function flagState(flags: AgentFlags | null | undefined, name: FlagName): FlagState {
  const value = flags?.[name];
  if (value === true) return 'set';
  if (value === false) return 'clear';
  return 'unknown';
}

/**
 * True when a registry record stands behind the agent. The API says so in `registration`; an
 * older API is read from the governance document, which only a registered agent has.
 */
export function hasRegistration(agent: Pick<Agent, 'registration' | 'governance'>): boolean {
  if (agent.registration) return agent.registration === 'registered';
  return !!agent.governance;
}

export type ReaderState = 'ok' | 'none' | 'unreachable';

/**
 * Whether the portal can read the account the agent's runtime is in. `none`: it has no reader
 * role there, so status, activity, policy and containment cannot be read. An agent that names
 * no runtime has nothing to read and counts as `ok`.
 */
export function readerState(agent: Pick<Agent, 'reader_status' | 'agent_arn'>): ReaderState {
  if (!agent.agent_arn) return 'ok';
  if (agent.reader_status === 'none') return 'none';
  if (agent.reader_status === 'unreachable') return 'unreachable';
  return 'ok';
}

const UNKNOWN_CLS = 'bg-white text-slate-700 border border-dashed border-slate-400';

export const NO_READER_TITLE = 'No reader role in this account';
export const NO_READER_CHIP: Tag = { label: NO_READER_TITLE, cls: UNKNOWN_CLS, hint: 'Status, activity, policy and containment cannot be read.' };
export const READER_UNREACHABLE_CHIP: Tag = {
  label: 'Reader role unreachable',
  cls: UNKNOWN_CLS,
  hint: 'The reader role in this account could not be used just now.',
};

/** "The portal has no role in this agent's account, so <what> cannot be read." */
export function noReaderSentence(what: string): string {
  return `The portal has no role in this agent’s account, so ${what} cannot be read.`;
}

type ChipAgent = Pick<Agent, 'flags' | 'reader_status' | 'agent_arn' | 'inventory_state' | 'registration' | 'governance'> &
  Partial<Pick<Agent, 'obligations_closed'>>;

/**
 * True for a retired registration with nothing deployed. The API then applies no risk rule, and
 * sends the flags about the record and its activity as null because they do not apply, not
 * because they could not be read. Such an agent is shown as retired, with no risk badge and no
 * flag chips, and none of its null flags is worded as unknown. Only the boolean `true` counts.
 */
export function obligationsClosed(agent: Partial<Pick<Agent, 'obligations_closed'>> | null | undefined): boolean {
  return agent?.obligations_closed === true;
}

export const NOT_APPLICABLE = 'Not applicable';
export const CLOSED_RISK_NOTE = 'This registration is retired and nothing is deployed, so no risk rule applies.';
export const CLOSED_RETIRED_NOTE =
  'This agent’s registration is retired, which is permanent, and nothing is deployed: nothing is left to do. To bring the agent back, register it again.';

/**
 * The chips shown next to an agent after its state, risk and containment badge.
 *
 * - A flag that is set: ownerless, review overdue, inactive. "No approved registration" is never
 *   a chip, because the state tag and the lifecycle already say it, and "Contained" has its own
 *   badge.
 * - What cannot be read: one chip for the whole account when the portal has no reader role
 *   there or cannot reach it. Otherwise one chip per fact that could not be read although a
 *   reader exists.
 * - Ownership and review do not apply to an agent that has no registration, and activity and
 *   containment do not apply to one that is not running, so those are never shown as unknown.
 */
export function agentChips(agent: ChipAgent): Tag[] {
  // Nothing about a retired registration with nothing deployed asks for attention or is unknown.
  if (obligationsClosed(agent)) return [];
  const flags = agent.flags;
  const chips: Tag[] = [];
  for (const name of ['ownerless', 'review_overdue', 'inactive'] as const) {
    // One or two words: kept on one line. The longer chips below may wrap in a narrow column.
    if (flagState(flags, name) === 'set') {
      chips.push({ label: FLAG_VIEW[name].label, cls: `${FLAG_VIEW[name].cls} whitespace-nowrap`, hint: FLAG_VIEW[name].hint });
    }
  }
  const reader = readerState(agent);
  if (reader === 'none') return [...chips, NO_READER_CHIP];
  if (reader === 'unreachable') return [...chips, READER_UNREACHABLE_CHIP];
  // An API that sent no flags at all has said nothing, so nothing is called unknown.
  if (!flags) return chips;
  const unknown = (name: FlagName): Tag => ({ label: FLAG_VIEW[name].unknown, cls: UNKNOWN_CLS, hint: 'This could not be read.' });
  const running = !!agent.agent_arn && agent.inventory_state !== 'registered_only';
  if (running) {
    for (const name of ['contained', 'inactive'] as const) if (flagState(flags, name) === 'unknown') chips.push(unknown(name));
  }
  if (hasRegistration(agent)) {
    for (const name of ['ownerless', 'review_overdue'] as const) if (flagState(flags, name) === 'unknown') chips.push(unknown(name));
  }
  return chips;
}

/** The choices of the flag filter. Only the two facts a reader reads can be "not readable". */
export const FLAG_FILTER_OPTIONS: { value: string; label: string }[] = [
  { value: 'unmanaged', label: FLAG_VIEW.unmanaged.label },
  { value: 'contained', label: FLAG_VIEW.contained.label },
  { value: 'ownerless', label: FLAG_VIEW.ownerless.label },
  { value: 'review_overdue', label: FLAG_VIEW.review_overdue.label },
  { value: 'inactive', label: FLAG_VIEW.inactive.label },
  { value: 'contained:unknown', label: 'Containment not readable' },
  { value: 'inactive:unknown', label: 'Activity not readable' },
];

/** The accountable person for an agent, or an empty string when none is recorded. */
export function sponsorOf(agent: Pick<Agent, 'governance' | 'sponsor'>): string {
  return (agent.sponsor ?? agent.governance?.sponsor ?? '').trim();
}

/** The date (YYYY-MM-DD) by which the registration must be reviewed again, or an empty string. */
export function reviewByOf(agent: Pick<Agent, 'governance' | 'review_by'>): string {
  return (agent.review_by ?? agent.governance?.review_by ?? '').trim();
}

/**
 * The agent's account for display: its configured alias, else its id masked to the last four
 * digits the way an ARN shows it. Never the full id. Empty when the account is not known.
 */
export function accountLabel(agent: Pick<Agent, 'account_alias' | 'account_id' | 'agent_arn'>): string {
  const alias = (agent.account_alias ?? '').trim();
  if (alias) return alias;
  const id = (agent.account_id ?? '').trim() || arnAccount(agent.agent_arn);
  return id ? maskAccountId(id) : '';
}

/**
 * What tells two agents of the same name apart: the tenant and the account, as in
 * "ws2 · workstream-ws2". Empty when neither is known.
 */
export function agentContext(agent: Pick<Agent, 'tenant_id' | 'account_alias' | 'account_id' | 'agent_arn'>, tenantName?: string | null): string {
  return [(tenantName ?? agent.tenant_id ?? '').trim(), accountLabel(agent)].filter(Boolean).join(' · ');
}

/**
 * Who created the agent's record, for display. The registry records an account id there: it is
 * shown as that account's alias when it is the agent's own account and has one, and masked
 * otherwise. Never a full account id.
 */
export function createdByLabel(agent: Pick<Agent, 'created_by' | 'account_id' | 'account_alias'>): string {
  const by = (agent.created_by ?? '').trim();
  if (!by) return '';
  const alias = (agent.account_alias ?? '').trim();
  if (alias && agent.account_id && by === agent.account_id) return alias;
  return maskAccountIds(by);
}

/** One line of the ownership card. `warn` marks something a person should act on. */
export interface OwnershipLine {
  text: string;
  tone: 'value' | 'muted' | 'warn';
  /** A remark shown under the value: the reason the agent is flagged. */
  note?: string;
}

const NO_REGISTRATION = 'None recorded (no registration)';

/** The API's sentence for the first of these reason codes that the agent carries, if any. */
function reasonSentence(agent: Pick<Agent, 'risk'>, codes: readonly string[]): string {
  const reason = (agent.risk?.reasons ?? []).find((r) => codes.includes(r.code));
  return reason?.detail?.trim() ?? '';
}

/**
 * The owner group, which is the agent's accountable owner. When the agent is flagged ownerless
 * the API's own reason is shown: the registration names no group, or names one that is not in
 * the owner roster.
 */
export function ownerGroupLine(
  agent: Pick<Agent, 'registration' | 'governance' | 'flags' | 'risk'> & Partial<Pick<Agent, 'obligations_closed'>>,
): OwnershipLine {
  const group = (agent.governance?.owner_group ?? '').trim();
  if (group) {
    return flagState(agent.flags, 'ownerless') === 'set'
      ? { text: group, tone: 'value', note: reasonSentence(agent, ['OWNER_GROUP_NOT_IN_ROSTER']) || 'This owner group is not in the owner roster.' }
      : { text: group, tone: 'value' };
  }
  if (!hasRegistration(agent)) return { text: NO_REGISTRATION, tone: 'muted' };
  // A retired registration with nothing deployed can no longer be corrected: stated, not raised.
  if (obligationsClosed(agent)) return { text: 'None recorded', tone: 'value' };
  return { text: 'None recorded', tone: 'warn', note: reasonSentence(agent, ['OWNERLESS']) || 'The registration names no owner group.' };
}

/** The accountable person. Optional: a registration without one is stated, not raised. */
export function sponsorLine(agent: Pick<Agent, 'registration' | 'governance' | 'sponsor'>): OwnershipLine {
  const sponsor = sponsorOf(agent);
  if (sponsor) return { text: sponsor, tone: 'value' };
  if (!hasRegistration(agent)) return { text: NO_REGISTRATION, tone: 'muted' };
  return { text: 'None recorded', tone: 'value' };
}

/** When the agent was last invoked, in words, when no date is recorded. */
export function lastInvokedText(
  agent: Pick<Agent, 'flags' | 'reader_status' | 'agent_arn' | 'inventory_state'> & Partial<Pick<Agent, 'obligations_closed'>>,
): string {
  // Nothing is deployed for a retired registration whose obligations are closed.
  if (obligationsClosed(agent)) return NOT_APPLICABLE;
  const reader = readerState(agent);
  if (reader === 'none') return `Not readable: ${NO_READER_TITLE.toLowerCase()}`;
  if (reader === 'unreachable') return 'Not readable just now';
  if (!agent.agent_arn || agent.inventory_state === 'registered_only') return 'Not running';
  return flagState(agent.flags, 'inactive') === 'unknown' ? 'Not readable' : 'No invocation in the inactivity window';
}

export function isContained(agent: Pick<Agent, 'flags'> | null | undefined): boolean {
  return flagState(agent?.flags, 'contained') === 'set';
}

/** A containment state that an action on the page has just verified, for one agent. */
export interface VerifiedContainment {
  id: string;
  contained: boolean;
}

/**
 * The agent with its `contained` flag replaced by the state an action has just verified. The
 * API serves flags from a short cache, so for a moment after a contain or release the agent
 * record can still carry the old value; the verified state is the newer fact. It applies only
 * to the agent it was verified for.
 */
export function withVerifiedContainment<T extends Pick<Agent, 'id' | 'flags'>>(agent: T, verified: VerifiedContainment | null): T {
  if (!verified || verified.id !== agent.id) return agent;
  return { ...agent, flags: { ...(agent.flags ?? {}), contained: verified.contained } };
}

/** Fields of an agent that an action on the page has just made true, for one agent. */
export interface VerifiedFields {
  id: string;
  fields: Partial<Agent>;
}

/**
 * The agent with the fields an action on this page has just changed. Like the containment flag,
 * the review date and the lifecycle are served from a short cache, so the record read right
 * after a review or a retirement can still carry the old values.
 *
 * `flags` in the verified fields is a patch: only the flags the action settled are overridden.
 * Every other flag stays as the API sends it, also when the agent is read again later.
 */
export function withVerifiedFields<T extends Pick<Agent, 'id' | 'flags'>>(agent: T, verified: VerifiedFields | null): T {
  if (!verified || verified.id !== agent.id) return agent;
  const { flags, ...rest } = verified.fields;
  return { ...agent, ...rest, flags: flags ? { ...(agent.flags ?? {}), ...flags } : agent.flags };
}

/** The lifecycle state of a retired registration. The registry calls it DEPRECATED. */
export const RETIRED_LIFECYCLE = 'deprecated';

export const RETIRED_STILL_DEPLOYED = 'The agent’s registration is retired and its runtime is still deployed.';
/** The follow-up the owner must do after a retirement. Shown with the reason above. */
export const RETIRED_FOLLOW_UP = 'What is left to do: the runtime must be removed by its pipeline. The portal removes nothing that is deployed.';

/**
 * Why a retired registration still needs someone: a detection source still sees the agent's
 * runtime. The API's own sentence when it sent one, or null when no runtime is detected.
 *
 * Right after a retirement the API has not assessed the agent again, so its reason is not there
 * yet. Whether a runtime is detected does not depend on the registration, and the API's rule is
 * exactly this one (retired, and a source still sees the runtime), so the page says it in its
 * own words until the API's sentence arrives.
 */
export function retiredRuntimeReason(agent: Pick<Agent, 'lifecycle_state' | 'risk' | 'inventory_state'>): string | null {
  if (agent.lifecycle_state !== RETIRED_LIFECYCLE) return null;
  const said = reasonSentence(agent, ['REGISTRATION_DEPRECATED']);
  if (said) return said;
  return agent.inventory_state === 'registered_and_detected' ? RETIRED_STILL_DEPLOYED : null;
}

/** When the registration was last attested as reviewed, in words. */
export function lastReviewedText(agent: Pick<Agent, 'last_reviewed_at' | 'last_reviewed_by'>, formatDate: (iso: string) => string): string {
  if (!agent.last_reviewed_at) return 'Not reviewed yet';
  const by = (agent.last_reviewed_by ?? '').trim();
  return by ? `${formatDate(agent.last_reviewed_at)} by ${by}` : formatDate(agent.last_reviewed_at);
}

/**
 * The tenants the caller acts for, when that is a real subset: the "My tenants" switch of the
 * agents list is offered only then. `["*"]` is every tenant (nothing to narrow to), and null or
 * an empty list means the caller has none or the API does not say.
 */
export function ownTenants(user: { registration_tenants?: unknown } | null | undefined): string[] | null {
  const raw = user?.registration_tenants;
  if (!Array.isArray(raw)) return null;
  const tenants = raw.filter((t): t is string => typeof t === 'string' && t.trim() !== '');
  if (tenants.length === 0 || tenants.includes('*')) return null;
  return tenants;
}

/** True when the agent belongs to one of these tenants. An agent with no tenant belongs to none. */
export function inTenants(agent: Pick<Agent, 'tenant_id'>, tenants: readonly string[]): boolean {
  return !!agent.tenant_id && tenants.includes(agent.tenant_id);
}

const RISK_VIEW: Record<RiskLevel, Tag> = {
  critical: { label: 'Critical risk', cls: 'bg-red-700 text-white' },
  high: { label: 'High risk', cls: 'bg-red-50 text-red-800' },
  medium: { label: 'Medium risk', cls: 'bg-amber-50 text-amber-900' },
  low: { label: 'Low risk', cls: 'bg-emerald-50 text-emerald-800' },
};

export const RISK_LEVELS: readonly RiskLevel[] = ['critical', 'high', 'medium', 'low'];

/** Risk tag with its level in words. Absent is "Risk not assessed", never "low". */
export function riskTag(level: string | null | undefined): Tag {
  if (!level) return { label: 'Risk not assessed', cls: 'bg-slate-100 text-slate-700' };
  return Object.prototype.hasOwnProperty.call(RISK_VIEW, level)
    ? RISK_VIEW[level as RiskLevel]
    : { label: `${level} risk`, cls: 'bg-slate-100 text-slate-700' };
}

const SEVERITY_LABEL: Record<string, string> = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Note' };

export function severityLabel(severity: string | null | undefined): string {
  const key = (severity ?? '').toLowerCase();
  return Object.prototype.hasOwnProperty.call(SEVERITY_LABEL, key) ? SEVERITY_LABEL[key] : severity || 'Note';
}

/** How an agent seen in telemetry relates to the inventory, in words. Never colour alone. */
export function observedTag(service: { registered?: boolean; detected?: boolean }): Tag {
  if (service.registered === true) return { label: 'Registered agent', cls: 'bg-emerald-50 text-emerald-800' };
  if (service.detected === true) {
    return { label: 'Detected, not registered', cls: 'bg-red-50 text-red-800', hint: 'A runtime the inventory knows that has no registration.' };
  }
  return {
    label: 'Observed in telemetry only',
    cls: 'bg-red-50 text-red-800',
    hint: 'This agent emits telemetry but was never registered or detected.',
  };
}

/** Where the listed agents were observed, in one sentence, or null when the API does not say. */
export function observedBy(domains: readonly { account_alias?: string | null; region?: string | null }[] | null | undefined): string | null {
  const places = (domains ?? [])
    .map((d) => (d.region ? `in ${d.region}${d.account_alias ? ` of ${d.account_alias}` : ''}` : d.account_alias ? `in the account ${d.account_alias}` : ''))
    .filter(Boolean);
  if (places.length === 0) return null;
  return `Observed by CloudWatch Omni ${[...new Set(places)].join(', and ')}.`;
}

/** The telemetry windows the fleet page offers. The API takes the window in hours, 1 to 168. */
export const OBSERVED_WINDOWS: { hours: number; label: string; words: string }[] = [
  { hours: 24, label: '24 hours', words: 'the last 24 hours' },
  { hours: 72, label: '3 days', words: 'the last 3 days' },
  { hours: 168, label: '7 days', words: 'the last 7 days' },
];

/** A window in words, for example "the last 3 days". An unlisted number of hours is stated as hours. */
export function windowWords(hours: number | null | undefined): string {
  const known = OBSERVED_WINDOWS.find((w) => w.hours === hours);
  if (known) return known.words;
  return typeof hours === 'number' && hours > 0 ? `the last ${hours} ${hours === 1 ? 'hour' : 'hours'}` : 'the selected window';
}

const SKIPPED_ACCOUNT = /^(.+): skipped, Omni is read only in the portal's own account\.?$/;

/**
 * Splits the API's notes about the telemetry read. An account that was skipped because Omni can
 * be read only in the portal's own account is information, not a problem: those accounts are
 * returned by name. Every other note stays a note.
 */
export function observedNotes(warnings: readonly string[] | null | undefined): { skipped: string[]; notes: string[] } {
  const skipped: string[] = [];
  const notes: string[] = [];
  for (const warning of warnings ?? []) {
    const match = SKIPPED_ACCOUNT.exec(warning.trim());
    if (match) skipped.push(match[1].trim());
    else if (warning.trim()) notes.push(warning);
  }
  return { skipped: [...new Set(skipped)], notes };
}

/** The muted line under the telemetry list that names the accounts that were not read. */
export function notReadLine(skipped: readonly string[]): string | null {
  if (skipped.length === 0) return null;
  return `Not read: ${skipped.join(', ')}. Omni can be read only in the portal’s own account.`;
}

/** A machine word such as `GEN_AI_AGENT` in readable form. */
export function humanise(word: string | null | undefined): string {
  const text = (word ?? '').trim();
  if (!text) return '';
  const lower = text.replace(/[_-]+/g, ' ').toLowerCase();
  return lower.charAt(0).toUpperCase() + lower.slice(1);
}

/** A reason in plain words: the server's sentence, or the code spelled out when it sent none. */
export function reasonText(reason: { code?: string | null; detail?: string | null }): string {
  const detail = reason.detail?.trim();
  if (detail) return detail;
  const code = (reason.code ?? '').trim();
  if (!code) return 'No explanation was given.';
  const words = code.replace(/[_-]+/g, ' ').toLowerCase();
  return words.charAt(0).toUpperCase() + words.slice(1);
}

/** The lifecycle filter value for "registered, not approved yet": every registration that is neither approved nor retired. */
export const AWAITING_APPROVAL = 'awaiting';

export interface InventoryFilters {
  /** A flag name, with `:unknown` appended to list agents whose flag could not be read. */
  flag: string;
  risk: string;
  state: string;
  /** A lifecycle state, or `awaiting` for every registration that is not approved. */
  lifecycle: string;
  /** An account as `accountLabel` words it: an alias or a masked id. */
  account: string;
}

export const NO_FILTERS: InventoryFilters = { flag: '', risk: '', state: '', lifecycle: '', account: '' };

const FILTER_KEYS = ['flag', 'risk', 'state', 'lifecycle', 'account'] as const;

/** Filters carried in the address, so a tile on the fleet page can link to a filtered list. */
export function filtersFromSearch(search: URLSearchParams): InventoryFilters {
  const filters = { ...NO_FILTERS };
  for (const key of FILTER_KEYS) filters[key] = search.get(key) ?? '';
  return filters;
}

export function searchFromFilters(filters: InventoryFilters): Record<string, string> {
  const out: Record<string, string> = {};
  for (const key of FILTER_KEYS) if (filters[key]) out[key] = filters[key];
  return out;
}

export function hasFilters(filters: InventoryFilters): boolean {
  return FILTER_KEYS.some((key) => !!filters[key]);
}

type FilterAgent = Pick<Agent, 'flags' | 'risk' | 'inventory_state'> &
  Partial<Pick<Agent, 'lifecycle_state' | 'registration' | 'governance' | 'account_alias' | 'account_id' | 'agent_arn' | 'obligations_closed'>>;

/** True when the agent passes every filter that is set. */
export function matchesFilters(agent: FilterAgent, filters: InventoryFilters): boolean {
  if (filters.flag) {
    const [name, want] = filters.flag.split(':');
    const state = flagState(agent.flags, name as FlagName);
    // A null flag of an agent whose obligations are closed does not apply: it is not "not readable".
    if (want === 'unknown' ? state !== 'unknown' || obligationsClosed(agent) : state !== 'set') return false;
  }
  if (filters.risk) {
    // An agent whose obligations are closed has no risk level to show: no rule applies to it.
    if (obligationsClosed(agent)) return false;
    if (filters.risk === 'none' ? !!agent.risk?.level : agent.risk?.level !== filters.risk) return false;
  }
  if (filters.state && agent.inventory_state !== filters.state) return false;
  if (filters.lifecycle) {
    if (filters.lifecycle === AWAITING_APPROVAL) {
      // Registered and not approved yet. A retired registration is neither: it is final.
      if (!hasRegistration(agent) || agent.lifecycle_state === 'approved' || agent.lifecycle_state === RETIRED_LIFECYCLE) return false;
    } else if (agent.lifecycle_state !== filters.lifecycle) return false;
  }
  if (filters.account && accountLabel(agent) !== filters.account) return false;
  return true;
}

/** The accounts the agents are in, as the account filter offers them: sorted, each once. */
export function accountOptions(agents: readonly Pick<Agent, 'account_alias' | 'account_id' | 'agent_arn'>[]): string[] {
  return [...new Set(agents.map(accountLabel).filter(Boolean))].sort((a, b) => a.localeCompare(b));
}

/**
 * The file name the server gave for the inventory export, reduced to a safe base name. Falls
 * back to `agents.<format>` when the header is absent, unreadable or names nothing usable.
 */
export function exportFilename(contentDisposition: string | null | undefined, format: string): string {
  return downloadFilename(contentDisposition, `agents.${format}`);
}

/** True for a link that may be opened: an absolute https URL. Anything else is not rendered. */
export function isSafeExternalUrl(url: string | null | undefined): url is string {
  if (!url) return false;
  try {
    return new URL(url).protocol === 'https:';
  } catch {
    return false;
  }
}
