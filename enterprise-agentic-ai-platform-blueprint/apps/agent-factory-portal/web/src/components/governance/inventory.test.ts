// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describe, expect, it } from 'vitest';
import {
  AWAITING_APPROVAL,
  FLAG_FILTER_OPTIONS,
  FLAG_NAMES,
  INVENTORY_STATE_OPTIONS,
  NO_FILTERS,
  NO_READER_CHIP,
  OBSERVED_WINDOWS,
  READER_UNREACHABLE_CHIP,
  accountLabel,
  accountOptions,
  agentChips,
  agentContext,
  createdByLabel,
  detectionSourceLabel,
  exportFilename,
  filtersFromSearch,
  flagLabel,
  flagState,
  hasFilters,
  hasRegistration,
  inTenants,
  inventoryStateTag,
  isContained,
  isSafeExternalUrl,
  lastInvokedText,
  lastReviewedText,
  matchesFilters,
  noReaderSentence,
  notReadLine,
  observedBy,
  observedNotes,
  observedTag,
  ownTenants,
  ownerGroupLine,
  readerState,
  reasonText,
  RETIRED_FOLLOW_UP,
  retiredRuntimeReason,
  reviewByOf,
  riskTag,
  searchFromFilters,
  severityLabel,
  sponsorLine,
  sponsorOf,
  windowWords,
  withVerifiedContainment,
  withVerifiedFields,
  CLOSED_RETIRED_NOTE,
  CLOSED_RISK_NOTE,
  obligationsClosed,
} from './inventory';

// Placeholder account ids: one repeated digit each.
const ACCOUNT = '1'.repeat(12);
const OTHER_ACCOUNT = '2'.repeat(12);
const ARN = `arn:aws:bedrock-agentcore:eu-west-1:${ACCOUNT}:runtime/orders-1`;
const ELSEWHERE_ARN = `arn:aws:bedrock-agentcore:eu-central-1:${OTHER_ACCOUNT}:runtime/elsewhere-1`;

describe('inventoryStateTag', () => {
  it('words the three states so that they read apart at a glance', () => {
    expect(inventoryStateTag('registered_and_detected').label).toBe('Registered');
    expect(inventoryStateTag('detected_only')).toMatchObject({ label: 'Not registered', hint: 'A runtime is running that nobody registered.' });
    expect(inventoryStateTag('registered_only').label).toBe('Registered, not running');
    expect(INVENTORY_STATE_OPTIONS.map((o) => o.value)).toEqual(['registered_and_detected', 'detected_only', 'registered_only']);
  });

  it('never says "unmanaged": the state and the lifecycle say what is wrong', () => {
    for (const option of INVENTORY_STATE_OPTIONS) expect(option.label).not.toMatch(/unmanaged/i);
  });

  it('says unknown for a missing state and shows an unrecognised one as recorded', () => {
    expect(inventoryStateTag(null).label).toBe('State unknown');
    expect(inventoryStateTag('archived').label).toBe('archived');
    expect(inventoryStateTag('constructor').label).toBe('constructor');
  });
});

describe('flags', () => {
  it('reads only true as set and only false as clear', () => {
    expect(flagState({ unmanaged: true }, 'unmanaged')).toBe('set');
    expect(flagState({ unmanaged: false }, 'unmanaged')).toBe('clear');
  });

  it('reads null, a missing flag and missing flags as unknown, never as false', () => {
    expect(flagState({ unmanaged: null }, 'unmanaged')).toBe('unknown');
    expect(flagState({}, 'unmanaged')).toBe('unknown');
    expect(flagState(null, 'unmanaged')).toBe('unknown');
    expect(flagState({ unmanaged: 'true' as never }, 'unmanaged')).toBe('unknown');
  });

  it('knows the five flags and labels an unknown name as recorded', () => {
    expect([...FLAG_NAMES].sort()).toEqual(['contained', 'inactive', 'ownerless', 'review_overdue', 'unmanaged']);
    expect(flagLabel('review_overdue')).toBe('Review overdue');
    expect(flagLabel('unmanaged')).toBe('No approved registration');
    expect(flagLabel('quarantined')).toBe('quarantined');
  });

  it('treats an agent as contained only when the flag is true', () => {
    expect(isContained({ flags: { contained: true } })).toBe(true);
    expect(isContained({ flags: { contained: null } })).toBe(false);
    expect(isContained({ flags: null })).toBe(false);
    expect(isContained(null)).toBe(false);
  });

  it('offers "No approved registration" as a filter, and "not readable" only for what a reader reads', () => {
    expect(FLAG_FILTER_OPTIONS.map((o) => o.value)).toEqual([
      'unmanaged',
      'contained',
      'ownerless',
      'review_overdue',
      'inactive',
      'contained:unknown',
      'inactive:unknown',
    ]);
    expect(FLAG_FILTER_OPTIONS[0].label).toBe('No approved registration');
    expect(FLAG_FILTER_OPTIONS.map((o) => o.label).join(' ')).not.toMatch(/unmanaged|unknown/i);
  });
});

describe('agentChips', () => {
  const labels = (agent: Parameters<typeof agentChips>[0]) => agentChips(agent).map((t) => t.label);
  const registered = { registration: 'registered', governance: { owner_group: 'retail-platform' }, inventory_state: 'registered_and_detected', agent_arn: ARN, reader_status: 'ok' } as const;
  const discovered = { registration: 'discovered', governance: null, inventory_state: 'detected_only', agent_arn: ARN, reader_status: 'ok' } as const;

  it('never shows a chip for "no approved registration", nor one for containment, which has its own badge', () => {
    expect(labels({ ...registered, flags: { unmanaged: true, contained: true, ownerless: false, review_overdue: false, inactive: false } })).toEqual([]);
    expect(labels({ ...discovered, flags: { unmanaged: true, contained: false, ownerless: null, review_overdue: null, inactive: false } })).toEqual([]);
  });

  it('shows the flags that are set, with the ownerless hint as the API defines it', () => {
    const chips = agentChips({ ...registered, flags: { unmanaged: false, contained: false, ownerless: true, review_overdue: true, inactive: true } });
    expect(chips.map((t) => t.label)).toEqual(['Ownerless', 'Review overdue', 'Inactive']);
    expect(chips[0].hint).toBe('No owner group, or one that is not in the owner roster.');
  });

  it('keeps the short flag chips on one line and lets the long reader chips wrap in a narrow column', () => {
    const chips = agentChips({ ...registered, flags: { unmanaged: false, contained: false, ownerless: true, review_overdue: true, inactive: true } });
    expect(chips.every((t) => t.cls.split(' ').includes('whitespace-nowrap'))).toBe(true);
    expect(NO_READER_CHIP.cls).not.toContain('whitespace-nowrap');
    expect(READER_UNREACHABLE_CHIP.cls).not.toContain('whitespace-nowrap');
  });

  it('shows one chip, not four, for an agent in an account with no reader role', () => {
    const flags = { unmanaged: true, contained: null, ownerless: null, review_overdue: null, inactive: null };
    expect(agentChips({ ...discovered, agent_arn: ELSEWHERE_ARN, reader_status: 'none', flags })).toEqual([NO_READER_CHIP]);
    expect(NO_READER_CHIP).toMatchObject({ label: 'No reader role in this account', hint: 'Status, activity, policy and containment cannot be read.' });
  });

  it('shows one chip when the reader role is unreachable', () => {
    const flags = { unmanaged: false, contained: null, ownerless: false, review_overdue: true, inactive: null };
    expect(labels({ ...registered, reader_status: 'unreachable', flags })).toEqual(['Review overdue', READER_UNREACHABLE_CHIP.label]);
  });

  it('never calls ownership or review unknown for an agent that has no registration', () => {
    expect(labels({ ...discovered, flags: { unmanaged: true, contained: false, ownerless: null, review_overdue: null, inactive: false } })).toEqual([]);
  });

  it('keeps an unknown chip for one fact that a reader could not read', () => {
    expect(labels({ ...registered, flags: { unmanaged: false, contained: null, ownerless: false, review_overdue: false, inactive: false } })).toEqual(['Containment unknown']);
    expect(labels({ ...discovered, flags: { unmanaged: true, contained: false, ownerless: null, review_overdue: null, inactive: null } })).toEqual(['Activity unknown']);
  });

  it('never calls activity or containment unknown for an agent that is not running', () => {
    const flags = { unmanaged: true, contained: null, ownerless: true, review_overdue: false, inactive: null };
    expect(labels({ registration: 'registered', governance: {}, inventory_state: 'registered_only', agent_arn: null, reader_status: 'none', flags })).toEqual(['Ownerless']);
    expect(labels({ registration: 'registered', governance: {}, inventory_state: 'registered_only', agent_arn: ARN, reader_status: 'ok', flags })).toEqual(['Ownerless']);
  });

  it('says nothing is unknown when the API sent no flags at all', () => {
    expect(labels({ ...registered, flags: null })).toEqual([]);
    expect(labels({ ...registered, flags: undefined })).toEqual([]);
  });
});

describe('readerState', () => {
  it('reads the three values, and treats an older API as readable', () => {
    expect(readerState({ reader_status: 'none', agent_arn: ARN })).toBe('none');
    expect(readerState({ reader_status: 'unreachable', agent_arn: ARN })).toBe('unreachable');
    expect(readerState({ reader_status: 'ok', agent_arn: ARN })).toBe('ok');
    expect(readerState({ agent_arn: ARN })).toBe('ok');
  });

  it('has nothing to read for an agent that names no runtime', () => {
    expect(readerState({ reader_status: 'none', agent_arn: null })).toBe('ok');
  });

  it('words what cannot be read plainly', () => {
    expect(noReaderSentence('its traces')).toBe('The portal has no role in this agent’s account, so its traces cannot be read.');
  });
});

describe('withVerifiedContainment', () => {
  const agent = { id: 'a-1', flags: { contained: false, inactive: true } };

  it('shows the state an action has just verified, although the agent record is still the old one', () => {
    const shown = withVerifiedContainment(agent, { id: 'a-1', contained: true });
    expect(isContained(shown)).toBe(true);
    expect(shown.flags).toEqual({ contained: true, inactive: true });
    expect(agent.flags.contained).toBe(false);
    expect(isContained(withVerifiedContainment({ id: 'a-1', flags: { contained: true } }, { id: 'a-1', contained: false }))).toBe(false);
  });

  it('applies only to the agent it was verified for, and leaves the record alone otherwise', () => {
    expect(withVerifiedContainment(agent, { id: 'other', contained: true })).toBe(agent);
    expect(withVerifiedContainment(agent, null)).toBe(agent);
  });

  it('works for an agent that carries no flags', () => {
    expect(isContained(withVerifiedContainment({ id: 'a-1', flags: null }, { id: 'a-1', contained: true }))).toBe(true);
  });
});

describe('withVerifiedFields', () => {
  const agent = { id: 'a-1', review_by: '2026-01-31', lifecycle_state: 'approved' as const, flags: { review_overdue: true } };

  it('shows what a review or a retirement on this page has just made true', () => {
    const shown = withVerifiedFields(agent, { id: 'a-1', fields: { review_by: '2027-05-27', flags: { review_overdue: false } } });
    expect(shown).toMatchObject({ id: 'a-1', review_by: '2027-05-27', lifecycle_state: 'approved', flags: { review_overdue: false } });
    expect(agent.review_by).toBe('2026-01-31');
  });

  it('applies only to the agent it was made for', () => {
    expect(withVerifiedFields(agent, { id: 'other', fields: { lifecycle_state: 'deprecated' } })).toBe(agent);
    expect(withVerifiedFields(agent, null)).toBe(agent);
  });

  it('patches only the flags the action settled, and keeps the others as the API sends them', () => {
    const before = { id: 'a-1', lifecycle_state: 'approved' as const, flags: { review_overdue: true, ownerless: true, inactive: false } };
    const verified = { id: 'a-1', fields: { lifecycle_state: 'deprecated' as const, flags: { review_overdue: false } } };
    expect(withVerifiedFields(before, verified).flags).toEqual({ review_overdue: false, ownerless: true, inactive: false });
    // The agent is read again later and the API has closed its obligations: its null flags come through.
    const later = { id: 'a-1', lifecycle_state: 'deprecated' as const, obligations_closed: true, flags: { review_overdue: null, ownerless: null, inactive: null } };
    expect(withVerifiedFields(later, verified)).toMatchObject({ obligations_closed: true, flags: { review_overdue: false, ownerless: null, inactive: null } });
    // Fields without flags leave the flags alone.
    expect(withVerifiedFields(before, { id: 'a-1', fields: { review_by: '2027-01-01' } }).flags).toBe(before.flags);
  });
});

describe('a retired registration with nothing deployed', () => {
  const closed = {
    registration: 'registered',
    governance: { owner_group: '' },
    inventory_state: 'registered_only',
    agent_arn: null,
    reader_status: 'ok',
    lifecycle_state: 'deprecated' as const,
    obligations_closed: true,
    risk: { level: 'low', reasons: [] },
    flags: { unmanaged: null, ownerless: null, review_overdue: null, inactive: null, contained: null },
  };

  it('is recognised only by the boolean true', () => {
    expect(obligationsClosed(closed)).toBe(true);
    expect(obligationsClosed({ obligations_closed: false })).toBe(false);
    expect(obligationsClosed({ obligations_closed: null })).toBe(false);
    expect(obligationsClosed({})).toBe(false);
    expect(obligationsClosed(null)).toBe(false);
    expect(obligationsClosed({ obligations_closed: 'true' as unknown as boolean })).toBe(false);
  });

  it('has no flag chips, and none of its null flags is called unknown', () => {
    expect(agentChips(closed)).toEqual([]);
    // The same flags on a registration that is not closed are unknown, and say so.
    expect(agentChips({ ...closed, obligations_closed: false }).map((t) => t.label).length).toBeGreaterThan(0);
    // Not even the reader chip: nothing is deployed that a reader could read.
    expect(agentChips({ ...closed, agent_arn: ELSEWHERE_ARN, reader_status: 'none' })).toEqual([]);
  });

  it('is not listed by the "not readable" filters nor at a risk level, and is by its lifecycle', () => {
    expect(matchesFilters(closed, { ...NO_FILTERS, flag: 'inactive:unknown' })).toBe(false);
    expect(matchesFilters(closed, { ...NO_FILTERS, flag: 'contained:unknown' })).toBe(false);
    expect(matchesFilters({ ...closed, obligations_closed: false }, { ...NO_FILTERS, flag: 'inactive:unknown' })).toBe(true);
    expect(matchesFilters(closed, { ...NO_FILTERS, flag: 'unmanaged' })).toBe(false);
    expect(matchesFilters(closed, { ...NO_FILTERS, lifecycle: 'deprecated' })).toBe(true);
    // The API sends level low for it, but no rule applies: it carries no risk badge and is under
    // no risk level. The fleet's Low risk tile leaves it out too, so the two agree.
    expect(matchesFilters(closed, { ...NO_FILTERS, risk: 'low' })).toBe(false);
    expect(matchesFilters(closed, { ...NO_FILTERS, risk: 'none' })).toBe(false);
    expect(matchesFilters({ ...closed, obligations_closed: false }, { ...NO_FILTERS, risk: 'low' })).toBe(true);
  });

  it('states a missing owner group without raising it, and has no activity to report', () => {
    expect(ownerGroupLine(closed)).toEqual({ text: 'None recorded', tone: 'value' });
    expect(ownerGroupLine({ ...closed, obligations_closed: false }).tone).toBe('warn');
    expect(lastInvokedText(closed)).toBe('Not applicable');
  });

  it('says in words why there is no risk level and that nothing is left to do', () => {
    expect(CLOSED_RISK_NOTE).toBe('This registration is retired and nothing is deployed, so no risk rule applies.');
    expect(CLOSED_RETIRED_NOTE).toMatch(/nothing is deployed: nothing is left to do\./);
    expect(retiredRuntimeReason(closed)).toBeNull();
  });
});

describe('retired registrations and reviews', () => {
  const reason = { code: 'REGISTRATION_DEPRECATED', severity: 'high', detail: 'The agent’s registration is retired (DEPRECATED) and its Runtime is still deployed.' };

  it('shows the API’s reason while a retired registration’s runtime is still deployed', () => {
    expect(retiredRuntimeReason({ lifecycle_state: 'deprecated', risk: { level: 'high', reasons: [reason] } })).toBe(reason.detail);
  });

  it('says nothing about a runtime once none is detected, or for a registration that is not retired', () => {
    expect(retiredRuntimeReason({ lifecycle_state: 'deprecated', risk: { level: 'low', reasons: [] } })).toBeNull();
    expect(retiredRuntimeReason({ lifecycle_state: 'deprecated', inventory_state: 'registered_only', risk: { level: 'low', reasons: [] } })).toBeNull();
    // Right after a retirement the API has not assessed the agent again: a runtime that is
    // detected is still deployed, and the page says so in its own words until the API does.
    expect(retiredRuntimeReason({ lifecycle_state: 'deprecated', inventory_state: 'registered_and_detected', risk: { level: 'high', reasons: [] } })).toBe(
      'The agent’s registration is retired and its runtime is still deployed.',
    );
    expect(retiredRuntimeReason({ lifecycle_state: 'deprecated', inventory_state: 'registered_and_detected', risk: { level: 'high', reasons: [reason] } })).toBe(reason.detail);
    expect(retiredRuntimeReason({ lifecycle_state: 'approved', inventory_state: 'registered_and_detected', risk: { level: 'low', reasons: [] } })).toBeNull();
    expect(RETIRED_FOLLOW_UP).toBe('What is left to do: the runtime must be removed by its pipeline. The portal removes nothing that is deployed.');
    expect(retiredRuntimeReason({ lifecycle_state: 'approved', risk: { level: 'high', reasons: [reason] } })).toBeNull();
  });

  it('says when a registration was last reviewed and by whom', () => {
    const format = (iso: string) => `on ${iso.slice(0, 10)}`;
    expect(lastReviewedText({ last_reviewed_at: '2026-11-27T10:00:00Z', last_reviewed_by: 'Example Approver' }, format)).toBe('on 2026-11-27 by Example Approver');
    expect(lastReviewedText({ last_reviewed_at: '2026-11-27T10:00:00Z', last_reviewed_by: ' ' }, format)).toBe('on 2026-11-27');
    expect(lastReviewedText({ last_reviewed_at: null }, format)).toBe('Not reviewed yet');
  });
});

describe('my tenants', () => {
  it('is offered only to a caller who acts for some tenants and not for all', () => {
    expect(ownTenants({ registration_tenants: ['ws1', 'ws2'] })).toEqual(['ws1', 'ws2']);
    // The platform role holds every tenant: there is nothing to narrow to.
    expect(ownTenants({ registration_tenants: ['*'] })).toBeNull();
    expect(ownTenants({ registration_tenants: ['ws1', '*'] })).toBeNull();
    expect(ownTenants({ registration_tenants: [] })).toBeNull();
    expect(ownTenants({ registration_tenants: null })).toBeNull();
    expect(ownTenants({})).toBeNull();
    expect(ownTenants(null)).toBeNull();
    expect(ownTenants({ registration_tenants: 'ws1' })).toBeNull();
    expect(ownTenants({ registration_tenants: ['ws1', 7, ' '] })).toEqual(['ws1']);
  });

  it('keeps the agents of those tenants; an agent with no tenant belongs to none', () => {
    expect(inTenants({ tenant_id: 'ws1' }, ['ws1', 'ws2'])).toBe(true);
    expect(inTenants({ tenant_id: 'ws3' }, ['ws1', 'ws2'])).toBe(false);
    expect(inTenants({ tenant_id: null }, ['ws1'])).toBe(false);
    expect(inTenants({}, ['ws1'])).toBe(false);
  });
});

describe('account and context', () => {
  it('shows the alias, else the account id masked the way an ARN shows it, never the full id', () => {
    expect(accountLabel({ account_alias: 'workstream-ws2', account_id: ACCOUNT, agent_arn: ARN })).toBe('workstream-ws2');
    expect(accountLabel({ account_alias: null, account_id: ACCOUNT })).toBe('••••1111');
    expect(accountLabel({ account_alias: ' ', agent_arn: ELSEWHERE_ARN })).toBe('••••2222');
    expect(accountLabel({})).toBe('');
    for (const agent of [{ account_id: ACCOUNT }, { agent_arn: ELSEWHERE_ARN }]) expect(accountLabel(agent)).not.toMatch(/\d{5}/);
  });

  it('tells two agents of one name apart by tenant and account', () => {
    expect(agentContext({ tenant_id: 'ws2', account_alias: 'workstream-ws2' })).toBe('ws2 · workstream-ws2');
    expect(agentContext({ tenant_id: 'ws2', account_alias: 'workstream-ws2' }, 'Workstream two')).toBe('Workstream two · workstream-ws2');
    expect(agentContext({ tenant_id: null, agent_arn: ELSEWHERE_ARN })).toBe('••••2222');
    expect(agentContext({ tenant_id: 'ws1' })).toBe('ws1');
    expect(agentContext({})).toBe('');
  });

  it('lists each account once, sorted, for the account filter', () => {
    expect(
      accountOptions([
        { account_alias: 'workstream-ws2' },
        { agent_arn: ELSEWHERE_ARN },
        { account_alias: 'workstream-ws1' },
        { account_alias: 'workstream-ws2' },
        {},
      ]),
    ).toEqual(['••••2222', 'workstream-ws1', 'workstream-ws2']);
  });

  it('never shows who created a record as a full account id', () => {
    expect(createdByLabel({ created_by: ACCOUNT, account_id: ACCOUNT, account_alias: 'retail-prod' })).toBe('retail-prod');
    expect(createdByLabel({ created_by: OTHER_ACCOUNT, account_id: ACCOUNT, account_alias: 'retail-prod' })).toBe('••••2222');
    expect(createdByLabel({ created_by: ACCOUNT })).toBe('••••1111');
    expect(createdByLabel({ created_by: `arn:aws:sts::${ACCOUNT}:assumed-role/pipeline/run` })).toBe('arn:aws:sts::••••1111:assumed-role/pipeline/run');
    expect(createdByLabel({ created_by: 'pipeline' })).toBe('pipeline');
    expect(createdByLabel({ created_by: null })).toBe('');
  });
});

describe('registration and ownership', () => {
  const registered = { registration: 'registered', governance: { owner_group: 'retail-platform' } } as const;

  it('reads whether a registration exists from the API, and from the governance document on an older API', () => {
    expect(hasRegistration({ registration: 'registered', governance: null })).toBe(true);
    expect(hasRegistration({ registration: 'discovered', governance: null })).toBe(false);
    expect(hasRegistration({ governance: {} })).toBe(true);
    expect(hasRegistration({ governance: null })).toBe(false);
    expect(hasRegistration({})).toBe(false);
  });

  it('reads the sponsor and the review date from the agent, then from its governance document', () => {
    expect(sponsorOf({ sponsor: ' Example Sponsor ', governance: { sponsor: 'other' } })).toBe('Example Sponsor');
    expect(sponsorOf({ governance: { sponsor: 'From Document' } })).toBe('From Document');
    expect(sponsorOf({ sponsor: null, governance: null })).toBe('');
    expect(reviewByOf({ review_by: '2027-01-31' })).toBe('2027-01-31');
    expect(reviewByOf({ governance: { review_by: '2026-06-30' } })).toBe('2026-06-30');
    expect(reviewByOf({})).toBe('');
  });

  it('treats the owner group as the accountable owner', () => {
    expect(ownerGroupLine({ ...registered, flags: { ownerless: false } })).toEqual({ text: 'retail-platform', tone: 'value' });
  });

  it('shows the API’s reason when the registration names no owner group', () => {
    const risk = { level: 'high', reasons: [{ code: 'OWNERLESS', severity: 'high', detail: 'The registration names no owner group.' }] };
    expect(ownerGroupLine({ registration: 'registered', governance: { owner_group: ' ' }, flags: { ownerless: true }, risk })).toEqual({
      text: 'None recorded',
      tone: 'warn',
      note: 'The registration names no owner group.',
    });
    // Without the reason the page still says what is wrong.
    expect(ownerGroupLine({ registration: 'registered', governance: {}, flags: { ownerless: true } }).note).toBe('The registration names no owner group.');
  });

  it('shows the API’s reason when the owner group is not in the roster', () => {
    const risk = {
      level: 'high',
      reasons: [{ code: 'OWNER_GROUP_NOT_IN_ROSTER', severity: 'high', detail: 'The registration’s owner group is not in the owner roster.' }],
    };
    expect(ownerGroupLine({ ...registered, flags: { ownerless: true }, risk })).toEqual({
      text: 'retail-platform',
      tone: 'value',
      note: 'The registration’s owner group is not in the owner roster.',
    });
    expect(ownerGroupLine({ ...registered, flags: { ownerless: true } }).note).toBe('This owner group is not in the owner roster.');
  });

  it('states a missing sponsor in the normal colour and nothing more: it is optional', () => {
    expect(sponsorLine({ ...registered, sponsor: 'Example Sponsor' })).toEqual({ text: 'Example Sponsor', tone: 'value' });
    expect(sponsorLine(registered)).toEqual({ text: 'None recorded', tone: 'value' });
    expect(sponsorLine({ registration: 'registered', governance: { owner_group: 'g', contact: 'team@example.com' } })).toEqual({ text: 'None recorded', tone: 'value' });
  });

  it('does not blame a missing registration on the owner or the sponsor', () => {
    const discovered = { registration: 'discovered', governance: null, flags: { ownerless: null } } as const;
    expect(ownerGroupLine(discovered)).toEqual({ text: 'None recorded (no registration)', tone: 'muted' });
    expect(sponsorLine(discovered)).toEqual({ text: 'None recorded (no registration)', tone: 'muted' });
  });

  it('says why the last invocation is not shown', () => {
    expect(lastInvokedText({ reader_status: 'none', agent_arn: ELSEWHERE_ARN, flags: { inactive: null } })).toBe('Not readable: no reader role in this account');
    expect(lastInvokedText({ reader_status: 'unreachable', agent_arn: ARN, flags: { inactive: null } })).toBe('Not readable just now');
    expect(lastInvokedText({ reader_status: 'ok', agent_arn: null, inventory_state: 'registered_only', flags: { inactive: null } })).toBe('Not running');
    expect(lastInvokedText({ reader_status: 'ok', agent_arn: ARN, inventory_state: 'detected_only', flags: { inactive: null } })).toBe('Not readable');
    expect(lastInvokedText({ reader_status: 'ok', agent_arn: ARN, inventory_state: 'registered_and_detected', flags: { inactive: true } })).toBe(
      'No invocation in the inactivity window',
    );
  });
});

describe('telemetry and detection wording', () => {
  it('names the detection sources in words and shows an unknown one as recorded', () => {
    expect(detectionSourceLabel('cell_reader')).toBe('Cell reader');
    expect(detectionSourceLabel('organization_registry')).toBe('Organization registry');
    expect(detectionSourceLabel('network_scan')).toBe('network_scan');
    expect(detectionSourceLabel('constructor')).toBe('constructor');
  });

  it('marks what matches no registered agent', () => {
    expect(observedTag({ registered: true, detected: true }).label).toBe('Registered agent');
    expect(observedTag({ registered: false, detected: true }).label).toBe('Detected, not registered');
    expect(observedTag({ registered: false, detected: false }).label).toBe('Observed in telemetry only');
    expect(observedTag({}).label).toBe('Observed in telemetry only');
  });

  it('says where the agents were observed, once per place', () => {
    expect(observedBy([{ account_alias: 'platform-nonprod', region: 'eu-west-1' }])).toBe('Observed by CloudWatch Omni in eu-west-1 of platform-nonprod.');
    expect(
      observedBy([
        { account_alias: 'platform-nonprod', region: 'eu-west-1' },
        { account_alias: 'platform-nonprod', region: 'eu-west-1' },
        { account_alias: 'platform-nonprod', region: 'us-east-1' },
      ]),
    ).toBe('Observed by CloudWatch Omni in eu-west-1 of platform-nonprod, and in us-east-1 of platform-nonprod.');
    expect(observedBy([{ account_alias: 'platform-nonprod' }])).toBe('Observed by CloudWatch Omni in the account platform-nonprod.');
    expect(observedBy([{ region: 'eu-west-1' }])).toBe('Observed by CloudWatch Omni in eu-west-1.');
    expect(observedBy([])).toBeNull();
    expect(observedBy(null)).toBeNull();
    expect(observedBy([{}])).toBeNull();
  });

  it('offers 24 hours, 3 days and 7 days, within what the API accepts', () => {
    expect(OBSERVED_WINDOWS.map((w) => [w.hours, w.label])).toEqual([
      [24, '24 hours'],
      [72, '3 days'],
      [168, '7 days'],
    ]);
    for (const w of OBSERVED_WINDOWS) expect(w.hours >= 1 && w.hours <= 168).toBe(true);
  });

  it('puts a window into words', () => {
    expect(windowWords(24)).toBe('the last 24 hours');
    expect(windowWords(72)).toBe('the last 3 days');
    expect(windowWords(168)).toBe('the last 7 days');
    expect(windowWords(36)).toBe('the last 36 hours');
    expect(windowWords(1)).toBe('the last 1 hour');
    expect(windowWords(null)).toBe('the selected window');
  });

  it('treats an account that Omni cannot be read in as information, and keeps every other note', () => {
    const { skipped, notes } = observedNotes([
      "workstream-ws2: skipped, Omni is read only in the portal's own account.",
      'platform: the Omni Context Graph in eu-west-1 could not be read (AccessDeniedException).',
      "workstream-ws1: skipped, Omni is read only in the portal's own account.",
      "workstream-ws2: skipped, Omni is read only in the portal's own account.",
      '  ',
    ]);
    expect(skipped).toEqual(['workstream-ws2', 'workstream-ws1']);
    expect(notes).toEqual(['platform: the Omni Context Graph in eu-west-1 could not be read (AccessDeniedException).']);
    expect(notReadLine(skipped)).toBe('Not read: workstream-ws2, workstream-ws1. Omni can be read only in the portal’s own account.');
    expect(notReadLine([])).toBeNull();
    expect(observedNotes(null)).toEqual({ skipped: [], notes: [] });
  });
});

describe('riskTag', () => {
  it('always carries the level in words', () => {
    expect(riskTag('critical').label).toBe('Critical risk');
    expect(riskTag('high').label).toBe('High risk');
    expect(riskTag('medium').label).toBe('Medium risk');
    expect(riskTag('low').label).toBe('Low risk');
  });

  it('never presents a missing or unknown level as low', () => {
    expect(riskTag(null).label).toBe('Risk not assessed');
    expect(riskTag('').label).toBe('Risk not assessed');
    expect(riskTag('severe').label).toBe('severe risk');
  });
});

describe('reasons', () => {
  it('uses the server sentence, and spells out the code when there is none', () => {
    expect(reasonText({ code: 'SPONSOR_MISSING', detail: 'The registration names no accountable person.' })).toBe(
      'The registration names no accountable person.',
    );
    expect(reasonText({ code: 'REVIEW_OVERDUE', detail: '  ' })).toBe('Review overdue');
    expect(reasonText({ code: '', detail: null })).toBe('No explanation was given.');
  });

  it('labels severities', () => {
    expect(severityLabel('HIGH')).toBe('High');
    expect(severityLabel('info')).toBe('Note');
    expect(severityLabel('blocker')).toBe('blocker');
    expect(severityLabel(null)).toBe('Note');
  });
});

describe('filters', () => {
  const agent = (over: object) => ({
    flags: { unmanaged: false, ownerless: null, contained: false },
    risk: { level: 'high', reasons: [] },
    inventory_state: 'registered_and_detected',
    lifecycle_state: 'approved' as const,
    registration: 'registered' as const,
    account_alias: 'workstream-ws1',
    ...over,
  });

  it('passes everything when no filter is set', () => {
    expect(matchesFilters(agent({}), NO_FILTERS)).toBe(true);
    expect(matchesFilters({ flags: null, risk: null, inventory_state: null }, NO_FILTERS)).toBe(true);
    expect(hasFilters(NO_FILTERS)).toBe(false);
  });

  it('filters by a set flag, and separately by a flag that could not be read', () => {
    expect(matchesFilters(agent({ flags: { unmanaged: true } }), { ...NO_FILTERS, flag: 'unmanaged' })).toBe(true);
    expect(matchesFilters(agent({}), { ...NO_FILTERS, flag: 'unmanaged' })).toBe(false);
    // An unknown flag is not counted as set...
    expect(matchesFilters(agent({ flags: { contained: null } }), { ...NO_FILTERS, flag: 'contained' })).toBe(false);
    // ...and can be found on its own.
    expect(matchesFilters(agent({ flags: { contained: null } }), { ...NO_FILTERS, flag: 'contained:unknown' })).toBe(true);
    expect(matchesFilters(agent({}), { ...NO_FILTERS, flag: 'contained:unknown' })).toBe(false);
  });

  it('filters by risk level, and finds agents with no assessment', () => {
    expect(matchesFilters(agent({}), { ...NO_FILTERS, risk: 'high' })).toBe(true);
    expect(matchesFilters(agent({}), { ...NO_FILTERS, risk: 'critical' })).toBe(false);
    expect(matchesFilters(agent({ risk: null }), { ...NO_FILTERS, risk: 'none' })).toBe(true);
    expect(matchesFilters(agent({}), { ...NO_FILTERS, risk: 'none' })).toBe(false);
  });

  it('filters by inventory state and combines filters', () => {
    expect(matchesFilters(agent({}), { ...NO_FILTERS, state: 'detected_only' })).toBe(false);
    expect(
      matchesFilters(agent({ inventory_state: 'detected_only', flags: { unmanaged: true } }), { ...NO_FILTERS, flag: 'unmanaged', risk: 'high', state: 'detected_only' }),
    ).toBe(true);
  });

  it('filters by lifecycle, and by "registered, not approved yet"', () => {
    expect(matchesFilters(agent({}), { ...NO_FILTERS, lifecycle: 'approved' })).toBe(true);
    expect(matchesFilters(agent({ lifecycle_state: 'pending_approval' }), { ...NO_FILTERS, lifecycle: 'approved' })).toBe(false);
    for (const state of ['pending_approval', 'proposed', 'rejected']) {
      expect(matchesFilters(agent({ lifecycle_state: state }), { ...NO_FILTERS, lifecycle: AWAITING_APPROVAL })).toBe(true);
    }
    expect(matchesFilters(agent({}), { ...NO_FILTERS, lifecycle: AWAITING_APPROVAL })).toBe(false);
    // A retired registration is final, not waiting: it has a filter of its own.
    expect(matchesFilters(agent({ lifecycle_state: 'deprecated' }), { ...NO_FILTERS, lifecycle: AWAITING_APPROVAL })).toBe(false);
    expect(matchesFilters(agent({ lifecycle_state: 'deprecated' }), { ...NO_FILTERS, lifecycle: 'deprecated' })).toBe(true);
    // An agent nobody registered is not awaiting approval: it is not registered.
    expect(
      matchesFilters(agent({ lifecycle_state: 'discovered', registration: 'discovered', inventory_state: 'detected_only' }), { ...NO_FILTERS, lifecycle: AWAITING_APPROVAL }),
    ).toBe(false);
  });

  it('filters by account, as the alias or the masked id', () => {
    expect(matchesFilters(agent({}), { ...NO_FILTERS, account: 'workstream-ws1' })).toBe(true);
    expect(matchesFilters(agent({}), { ...NO_FILTERS, account: 'workstream-ws2' })).toBe(false);
    expect(matchesFilters(agent({ account_alias: null, agent_arn: ELSEWHERE_ARN }), { ...NO_FILTERS, account: '••••2222' })).toBe(true);
  });

  it('round-trips through the address', () => {
    const filters = { flag: 'review_overdue', risk: 'medium', state: '', lifecycle: AWAITING_APPROVAL, account: 'workstream-ws2' };
    expect(searchFromFilters(filters)).toEqual({ flag: 'review_overdue', risk: 'medium', lifecycle: 'awaiting', account: 'workstream-ws2' });
    expect(filtersFromSearch(new URLSearchParams(searchFromFilters(filters)))).toEqual(filters);
    expect(filtersFromSearch(new URLSearchParams(''))).toEqual(NO_FILTERS);
    expect(hasFilters(filters)).toBe(true);
  });
});

describe('exportFilename', () => {
  it('uses the name the server sent', () => {
    expect(exportFilename('attachment; filename="agent-inventory-2026-11-27.csv"', 'csv')).toBe('agent-inventory-2026-11-27.csv');
    expect(exportFilename('attachment; filename=inventory.json', 'json')).toBe('inventory.json');
    expect(exportFilename("attachment; filename*=UTF-8''agent%20inventory.csv", 'csv')).toBe('agent inventory.csv');
  });

  it('falls back when the header is absent or names nothing', () => {
    expect(exportFilename(null, 'csv')).toBe('agents.csv');
    expect(exportFilename('attachment', 'json')).toBe('agents.json');
    expect(exportFilename('attachment; filename=""', 'csv')).toBe('agents.csv');
  });

  it('keeps only a safe base name', () => {
    expect(exportFilename('attachment; filename="../../etc/passwd"', 'csv')).toBe('passwd');
    expect(exportFilename('attachment; filename="..\\..\\boot.ini"', 'csv')).toBe('boot.ini');
    expect(exportFilename('attachment; filename="a<b>c:d.csv"', 'csv')).toBe('a_b_c_d.csv');
    expect(exportFilename('attachment; filename=".hidden"', 'csv')).toBe('hidden');
    expect(exportFilename("attachment; filename*=UTF-8''%E0%A4%A", 'csv')).toBe('agents.csv');
  });
});

describe('isSafeExternalUrl', () => {
  it('accepts only absolute https URLs', () => {
    expect(isSafeExternalUrl('https://console.example.com/omni?service=orders')).toBe(true);
    for (const bad of ['http://console.example.com/', 'javascript:alert(1)', 'data:text/html,x', '/relative', '//host/path', '', null, undefined]) {
      expect(isSafeExternalUrl(bad)).toBe(false);
    }
  });
});
