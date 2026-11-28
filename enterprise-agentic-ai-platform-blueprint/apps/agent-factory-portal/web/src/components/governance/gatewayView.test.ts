// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describe, expect, it } from 'vitest';
import {
  CONNECTED_NOT_KNOWN,
  NOT_READABLE,
  READER_FILTER_OPTIONS,
  gatewayAccount,
  gatewayChip,
  gatewayDetectedBy,
  gatewayLifecycle,
  gatewayNotRead,
  gatewayRead,
  gatewayReader,
  knownTime,
  matchesGateway,
  policyCell,
  toolsCell,
  unreadNote,
} from './gatewayView';
import { NO_READER_CHIP } from './inventory';

// Placeholder account ids: one repeated digit.
const ACCOUNT = '2'.repeat(12);
const ARN = `arn:aws:bedrock-agentcore:eu-central-1:${ACCOUNT}:gateway/payments-gateway-abc123`;
const API_SENTENCE = 'There is no reader role in this gateway’s account, so its targets, its policy engine and its policies cannot be shown.';

describe('gatewayReader', () => {
  it('reads a gateway as read when the API says so, or does not say', () => {
    expect(gatewayReader({ reader_status: 'ok' })).toBe('ok');
    expect(gatewayReader({})).toBe('ok');
    expect(gatewayReader({ reader_status: null })).toBe('ok');
    expect(gatewayReader(null)).toBe('ok');
    expect(gatewayRead({ reader_status: ' OK ' })).toBe(true);
  });

  it('tells the three reasons a gateway was not read apart', () => {
    expect(gatewayReader({ reader_status: 'none' })).toBe('none');
    expect(gatewayReader({ reader_status: 'unreachable' })).toBe('unreachable');
    expect(gatewayReader({ reader_status: 'not_listed' })).toBe('not_listed');
    expect(gatewayRead({ reader_status: 'none' })).toBe(false);
  });

  it('never takes a status it does not know for "read"', () => {
    expect(gatewayReader({ reader_status: 'quarantined' })).toBe('unread');
    expect(gatewayRead({ reader_status: 'quarantined' })).toBe(false);
  });
});

describe('gatewayNotRead', () => {
  it('says nothing for a gateway a reader read', () => {
    expect(gatewayNotRead({ reader_status: 'ok', detail: null })).toBeNull();
    expect(gatewayChip({ reader_status: 'ok' })).toBeNull();
  });

  it('gives the API’s own sentence when it sent one', () => {
    expect(gatewayNotRead({ reader_status: 'none', detail: API_SENTENCE })).toEqual({ title: 'No reader role in this account', sentence: API_SENTENCE });
  });

  it('words each reason itself when the API sent no sentence', () => {
    expect(gatewayNotRead({ reader_status: 'none' })?.sentence).toBe(
      'The portal has no role in this gateway’s account, so its tools, its policy engine and its policies cannot be shown.',
    );
    expect(gatewayNotRead({ reader_status: 'unreachable', detail: ' ' })).toEqual({
      title: 'Reader role unreachable',
      sentence: 'The reader role in this gateway’s account could not be used just now, so its tools, its policy engine and its policies cannot be shown.',
    });
    const notListed = gatewayNotRead({ reader_status: 'not_listed' });
    expect(notListed?.title).toBe('Not listed by the reader');
    expect(notListed?.sentence).toMatch(/It may have been deleted since the organization registry detected it\.$/);
    expect(gatewayNotRead({ reader_status: 'something-new' })).toEqual({
      title: 'Not read',
      sentence: 'No reader read this gateway, so its tools, its policy engine and its policies cannot be shown.',
    });
  });

  it('marks such a gateway with the same chip an agent in that account carries', () => {
    const chip = gatewayChip({ reader_status: 'none', detail: API_SENTENCE });
    expect(chip).toEqual({ label: NO_READER_CHIP.label, cls: NO_READER_CHIP.cls, hint: API_SENTENCE });
  });
});

describe('what the list shows', () => {
  const read = { reader_status: 'ok', available_tools: [{ name: 'a', input_schema: {} }, { name: 'b', input_schema: {} }], cedar_enforcement_mode: 'enforce' };
  const unread = { reader_status: 'none', available_tools: [], cedar_enforcement_mode: 'unknown' };

  it('counts the tools of a gateway a reader read, zero included', () => {
    expect(toolsCell(read)).toBe('2');
    expect(toolsCell({ reader_status: 'ok', available_tools: [] })).toBe('0');
  });

  it('never shows "0" tools or "no policy engine" for a gateway no reader read', () => {
    expect(toolsCell(unread)).toBe(NOT_READABLE);
    expect(policyCell(unread)).toBe(NOT_READABLE);
    // Even if such a gateway came with a mode that reads as "none".
    expect(policyCell({ reader_status: 'none', cedar_enforcement_mode: 'none' })).toBe(NOT_READABLE);
    expect(NOT_READABLE).toBe('Not readable');
  });

  it('words the policy mode of a gateway a reader read, and an unknown mode as unknown', () => {
    expect(policyCell(read)).toBe('Enforcing (default deny)');
    expect(policyCell({ reader_status: 'ok', cedar_enforcement_mode: 'none' })).toBe('No policy engine attached');
    expect(policyCell({ reader_status: 'ok', cedar_enforcement_mode: 'unknown' })).toBe('Enforcement mode unknown');
  });

  it('calls a gateway in an account with no reader role "Not managed here", and any other unread one "Detected only"', () => {
    expect(gatewayLifecycle({ reader_status: 'none', lifecycle_state: 'discovered' })).toEqual({ cls: 'bg-sky-50 text-sky-700', label: 'Not managed here' });
    // The reader role exists there: the account is managed here, the gateway was just not read.
    expect(gatewayLifecycle({ reader_status: 'unreachable', lifecycle_state: 'discovered' }).label).toBe('Detected only');
    expect(gatewayLifecycle({ reader_status: 'not_listed', lifecycle_state: 'discovered' }).label).toBe('Detected only');
    expect(gatewayLifecycle({ reader_status: 'something-new', lifecycle_state: 'discovered' }).label).toBe('Detected only');
    expect(gatewayLifecycle({ reader_status: 'ok', lifecycle_state: 'discovered' }).label).toBe('Detected only');
    expect(gatewayLifecycle({ reader_status: 'ok', lifecycle_state: 'approved' }).label).toBe('Approved');
    expect(gatewayLifecycle({ reader_status: 'ok', lifecycle_state: 'proposed' }).label).toBe('Proposed');
  });

  it('shows the account by its alias, else masked, never in full', () => {
    expect(gatewayAccount({ account_alias: 'payments-prod', account_id: ACCOUNT, gateway_arn: ARN })).toBe('payments-prod');
    expect(gatewayAccount({ account_alias: null, account_id: ACCOUNT, gateway_arn: ARN })).toBe('••••2222');
    expect(gatewayAccount({ gateway_arn: ARN })).toBe('••••2222');
    expect(gatewayAccount({})).toBe('');
  });

  it('says what detected the gateway, in words', () => {
    expect(gatewayDetectedBy({ detection_sources: ['organization_registry'] })).toBe('Organization registry');
    expect(gatewayDetectedBy({ detection_sources: ['cell_reader', 'organization_registry'] })).toBe('Cell reader, Organization registry');
    expect(gatewayDetectedBy({ detection_sources: null })).toBe('');
    expect(gatewayDetectedBy({})).toBe('');
  });
});

describe('knownTime', () => {
  it('keeps a real time and drops the epoch the API sends when it cannot know one', () => {
    expect(knownTime('2026-11-27T10:00:00Z')).toBe('2026-11-27T10:00:00Z');
    expect(knownTime('1970-01-01T00:00:00Z')).toBeNull();
    expect(knownTime('')).toBeNull();
    expect(knownTime(null)).toBeNull();
    expect(knownTime('not a date')).toBeNull();
  });
});

describe('matchesGateway', () => {
  const read = { name: 'orders-gateway', reader_status: 'ok', account_alias: 'retail-prod', gateway_arn: ARN };
  const unread = { name: 'payments-gateway', reader_status: 'none', account_id: ACCOUNT, gateway_arn: ARN };

  it('filters by whether a reader read the gateway', () => {
    expect(matchesGateway(read, '', 'all')).toBe(true);
    expect(matchesGateway(unread, '', 'all')).toBe(true);
    expect(matchesGateway(read, '', 'read')).toBe(true);
    expect(matchesGateway(unread, '', 'read')).toBe(false);
    expect(matchesGateway(read, '', 'unread')).toBe(false);
    expect(matchesGateway(unread, '', 'unread')).toBe(true);
    expect(READER_FILTER_OPTIONS.map((o) => o.value)).toEqual(['all', 'read', 'unread']);
  });

  it('searches the name and the account as shown, never the full account id', () => {
    expect(matchesGateway(read, ' ORDERS ', 'all')).toBe(true);
    expect(matchesGateway(read, 'retail-prod', 'all')).toBe(true);
    expect(matchesGateway(unread, '2222', 'all')).toBe(true);
    expect(matchesGateway(unread, ACCOUNT, 'all')).toBe(false);
    expect(matchesGateway(read, 'payments', 'all')).toBe(false);
  });
});

describe('unreadNote', () => {
  it('says above the list how many gateways no reader read, and nothing when there is none', () => {
    expect(unreadNote(0)).toBeNull();
    expect(unreadNote(Number.NaN)).toBeNull();
    expect(unreadNote(1)).toBe('1 gateway is listed from the organization registry only: no reader role read it, so its tools and policies cannot be shown.');
    expect(unreadNote(9)).toBe('9 gateways are listed from the organization registry only: no reader role read them, so their tools and policies cannot be shown.');
  });
});

describe('connected agents of a gateway no reader read', () => {
  it('says that they are not shown, and where an agent’s own subscription is', () => {
    expect(CONNECTED_NOT_KNOWN).toMatch(/^Which agents are connected to it is therefore not shown here\./);
    expect(CONNECTED_NOT_KNOWN).toMatch(/Tool subscriptions\.$/);
  });
});
