// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { afterEach, describe, expect, it, vi } from 'vitest';
import client from '../api/client';
import tabSrc from './ContainmentTab.tsx?raw';
import { containmentApi, type ContainmentResult, type ContainmentView } from './containmentClient';
import {
  INCIDENT_RECORD_NOTE,
  NOT_ENABLED_NOTE,
  NOT_READABLE,
  NO_CONTAIN_AUTHORITY_NOTE,
  NO_RELEASE_AUTHORITY_NOTE,
  REPEAT_AFTER_SECONDS,
  REPEAT_TOO_SOON_CAVEAT,
  SAME_PERSON_NOTE,
  SWEEPS_OVERDUE_NOTE,
  SWEEP_POLL_LIMIT,
  SWEEP_POLL_SECONDS,
  UNKNOWN_STATE_NOTE,
  containEffects,
  CONTAIN_DELAY_SECONDS,
  RELEASE_DELAY_SECONDS,
  aboutDuration,
  containmentState,
  eventActionLabel,
  hasNoRuntime,
  incompleteWords,
  isPartial,
  lastSweepFailed,
  offeredContainment,
  releaseEffects,
  repeatEffects,
  repeatMayComeTooSoon,
  resultHeadline,
  retryAfterSeconds,
  retryNote,
  sessionsMayRemain,
  sessionsStatus,
  sessionsText,
  showsIncidentRecord,
  SWEEPS_GIVEN_UP_SECONDS,
  splitReason,
  stateCard,
  stepStatusView,
  stepsFromFailure,
  sweepCounts,
  sweepLines,
  sweepOutcomeLabel,
  sweepsNotScheduled,
  sweepsOverdue,
  sweepsPending,
} from './containmentView';
import type { AuditEvent } from './registrationsClient';
import { HISTORY_TRUNCATED_NOTE, historyRows, outcomeView } from './registrationView';

// A placeholder account id: one repeated digit.
const RUNTIME_ARN = `arn:aws:bedrock-agentcore:eu-west-1:${'1'.repeat(12)}:runtime/found-1`;

describe('containmentApi', () => {
  afterEach(() => vi.restoreAllMocks());

  it('reads with GET and writes with POST, only under the agent’s containment path', async () => {
    const get = vi.spyOn(client, 'get').mockResolvedValue({ data: {} });
    const post = vi.spyOn(client, 'post').mockResolvedValue({ data: {} });
    await containmentApi.get('agent 1');
    await containmentApi.contain('agent-1', 'Leaking customer data.');
    await containmentApi.release('agent-1', 'Fixed and reviewed.');
    expect(get.mock.calls).toEqual([['/agents/agent%201/containment']]);
    expect(post.mock.calls).toEqual([
      ['/agents/agent-1/containment/contain', { reason: 'Leaking customer data.' }],
      ['/agents/agent-1/containment/release', { reason: 'Fixed and reviewed.' }],
    ]);
  });

  it('names the runtime only when one is given, for an agent that has no registration', async () => {
    const post = vi.spyOn(client, 'post').mockResolvedValue({ data: {} });
    await containmentApi.contain('found-1', 'Unregistered.', RUNTIME_ARN);
    await containmentApi.contain('agent-1', 'Registered.', null);
    expect(post.mock.calls[0][1]).toEqual({ reason: 'Unregistered.', runtime_arn: RUNTIME_ARN });
    expect(post.mock.calls[1][1]).toEqual({ reason: 'Registered.' });
  });
});

describe('containmentState', () => {
  it('reads only the exact words', () => {
    expect(containmentState({ state: 'contained' })).toBe('contained');
    expect(containmentState({ state: ' CONTAINED ' })).toBe('contained');
    expect(containmentState({ state: 'not_contained' })).toBe('not_contained');
  });

  it('never reads an unknown or missing state as not contained', () => {
    for (const state of ['', 'unknown', 'partial', 'constructor', 'released']) {
      expect(containmentState({ state })).toBe('unknown');
    }
    expect(containmentState(null)).toBe('unknown');
  });
});

describe('offeredContainment', () => {
  const both = { canContain: true, canRelease: true };
  const containOnly = { canContain: true, canRelease: false };
  const neither = { canContain: false, canRelease: false };
  const none = { contain: false, release: false, repeat: false, releaseBlocked: false };

  it('offers Contain to a holder of the authority when the agent is not contained', () => {
    expect(offeredContainment({ state: 'not_contained' }, containOnly)).toEqual({ ...none, contain: true, note: null });
    expect(offeredContainment({ state: 'not_contained' }, neither)).toEqual({ ...none, note: NO_CONTAIN_AUTHORITY_NOTE });
  });

  it('offers Release to a different person who holds the authority to release', () => {
    expect(offeredContainment({ state: 'contained', contained_by_me: false }, both)).toEqual({ ...none, release: true, note: null });
    expect(offeredContainment({ state: 'contained' }, both).release).toBe(true);
  });

  it('shows Release as unavailable to the person who contained the agent, with the reason', () => {
    expect(offeredContainment({ state: 'contained', contained_by_me: true }, both)).toEqual({ ...none, releaseBlocked: true, note: SAME_PERSON_NOTE });
    expect(SAME_PERSON_NOTE).toBe('You contained this agent. A different person must release it.');
  });

  it('does not show Release at all to someone who may contain but not release', () => {
    expect(offeredContainment({ state: 'contained', contained_by_me: false }, containOnly)).toEqual({ ...none, note: NO_RELEASE_AUTHORITY_NOTE });
    // Not holding the authority comes first: the two-person rule is not the reason then.
    expect(offeredContainment({ state: 'contained', contained_by_me: true }, containOnly)).toEqual({ ...none, note: NO_RELEASE_AUTHORITY_NOTE });
  });

  it('offers nothing when the agent’s cell has not enabled containment, and says why', () => {
    expect(offeredContainment({ state: 'not_contained', enabled: false }, both)).toEqual({ ...none, note: NOT_ENABLED_NOTE });
    expect(offeredContainment({ state: 'contained', enabled: false }, both).release).toBe(false);
    expect(offeredContainment({ state: 'contained', enabled: false, contained_by_me: true }, both).releaseBlocked).toBe(false);
    expect(offeredContainment({ state: 'not_contained', enabled: true }, both).contain).toBe(true);
    expect(NOT_ENABLED_NOTE).toBe('Containment is not available for this agent. Its cell has not given the portal the authority to contain it.');
  });

  it('offers nothing while the state is unknown', () => {
    expect(offeredContainment({ state: 'unknown' }, both)).toEqual({ ...none, note: UNKNOWN_STATE_NOTE });
    expect(offeredContainment(null, both)).toEqual({ ...none, note: UNKNOWN_STATE_NOTE });
    expect(offeredContainment({ state: 'unknown' }, neither).note).toBeNull();
  });

  it('gives the unreadable state as the reason, not the cell, when a state that cannot be read comes with enabled false', () => {
    // A registration that spells its runtime's ARN another way: the API sends unknown, its own
    // sentence in detail, and enabled false. The cell may well have enabled containment.
    const view = { state: 'unknown', enabled: false, runtime_arn: RUNTIME_ARN, detail: 'The registration names its Runtime by an ARN whose partition is not the one of the Runtime’s cell, so its containment state was not read.' };
    expect(offeredContainment(view, both)).toEqual({ ...none, note: UNKNOWN_STATE_NOTE });
    expect(offeredContainment(view, both).note).not.toBe(NOT_ENABLED_NOTE);
    expect(offeredContainment(view, neither).note).toBeNull();
    // A state that was read keeps the cell's reason.
    expect(offeredContainment({ ...view, state: 'not_contained' }, both).note).toBe(NOT_ENABLED_NOTE);
    expect(offeredContainment({ ...view, state: 'contained' }, both).note).toBe(NOT_ENABLED_NOTE);
  });

  it('offers nothing for an agent that has no runtime, and leaves the explanation to the state card', () => {
    expect(offeredContainment({ state: 'unknown', enabled: false, runtime_arn: null }, both)).toEqual({ ...none, note: null });
    // An API that does not send the field is not read as "no runtime": the state is unknown, and the page says that.
    expect(offeredContainment({ state: 'unknown', enabled: false }, both).note).toBe(UNKNOWN_STATE_NOTE);
  });

  describe('stopping the sessions that are left', () => {
    const left = { state: 'contained', partial: true, sweeps: { scheduled: 0, done: 0 }, quiet_at: null };

    it('offers the contain again to whoever may contain, beside the release', () => {
      expect(offeredContainment(left, both)).toEqual({ ...none, repeat: true, release: true, note: null });
      // The role that may contain but not release keeps its remedy.
      expect(offeredContainment(left, containOnly)).toEqual({ ...none, repeat: true, note: NO_RELEASE_AUTHORITY_NOTE });
      expect(offeredContainment(left, neither).repeat).toBe(false);
    });

    it('offers it to the person who contained the agent too: it does not change who holds the containment', () => {
      expect(offeredContainment({ ...left, contained_by_me: true }, both)).toEqual({
        ...none,
        repeat: true,
        releaseBlocked: true,
        note: SAME_PERSON_NOTE,
      });
    });

    it('does not hold it back while a sweep has yet to report: one that was lost never does', () => {
      // If the contain comes too soon the API answers at once and says when one does its work
      // again. The page does not guard against sending it.
      expect(offeredContainment({ ...left, sweeps: { scheduled: 3, done: 1 } }, both)).toMatchObject({ repeat: true, release: true });
      expect(offeredContainment({ ...left, sweeps: { scheduled: 3, done: 3 } }, both).repeat).toBe(true);
      // Never offered to someone who may not contain, or once quiet is confirmed.
      expect(offeredContainment({ ...left, sweeps: { scheduled: 3, done: 1 } }, neither).repeat).toBe(false);
      expect(offeredContainment({ ...left, sweeps: { scheduled: 3, done: 1 }, quiet_at: '2026-11-28T01:30:00Z' }, both).repeat).toBe(false);
    });

    it('offers it for a clean containment whose sweeps never reported, once they are given up', () => {
      const began = '2026-11-28T01:00:00.000000Z';
      const lost = { state: 'contained', partial: false, sweeps: { scheduled: 2, done: 0 }, quiet_at: null, contained_at: began };
      const at = (minutes: number) => Date.parse(began) + minutes * 60_000;
      expect(SWEEPS_GIVEN_UP_SECONDS).toBe(1800);
      // Still within the half hour in which a sweep can be running: the sweeps are trusted.
      expect(sweepsOverdue(lost, at(29))).toBe(false);
      expect(offeredContainment(lost, both, at(29)).repeat).toBe(false);
      // After it: the counts will stay "0 of 2 done" for good, and containing again is the way on.
      expect(sweepsOverdue(lost, at(30))).toBe(true);
      expect(offeredContainment(lost, both, at(31)).repeat).toBe(true);
      // Not for sweeps that all reported, a containment by other means, or without a clock.
      expect(sweepsOverdue({ ...lost, sweeps: { scheduled: 2, done: 2 } }, at(90))).toBe(false);
      expect(sweepsOverdue({ ...lost, contained_at: null }, at(90))).toBe(false);
      expect(sweepsOverdue(lost, 0)).toBe(false);
      expect(offeredContainment(lost, both).repeat).toBe(false);
      expect(sweepsOverdue(null, at(90))).toBe(false);
    });

    it('counts the half hour from the newest contain that did its work, not from one answered at once', () => {
      const began = '2026-11-28T01:00:00.000000Z';
      const event = (over: Partial<AuditEvent>): AuditEvent => ({
        event_id: 'e', request_id: 'r', at: began, phase: 'result', action: 'contain', outcome: 'allowed', reason: '', actor_label: 'sam@example.com', ...over,
      });
      const view = (events: AuditEvent[]) => ({ state: 'contained', partial: false, sweeps: { scheduled: 4, done: 2 }, quiet_at: null, contained_at: began, events });
      // A repeat at 01:20 did its work (it carries session counts) and scheduled sweeps of its own.
      const worked = event({ event_id: 'c2', outcome: 'unchanged', at: '2026-11-28T01:20:00.000000Z', sessions_found: 0 });
      // A repeat at 01:40 was answered at once: no session counts.
      const atOnce = event({ event_id: 'c3', outcome: 'unchanged', at: '2026-11-28T01:40:00.000000Z', sessions_found: null });
      const first = event({ event_id: 'c1', sessions_found: 2 });
      const now = (iso: string) => Date.parse(iso);
      expect(sweepsOverdue(view([atOnce, worked, first]), now('2026-11-28T01:49:00Z'))).toBe(false);
      expect(sweepsOverdue(view([atOnce, worked, first]), now('2026-11-28T01:50:00Z'))).toBe(true);
      // An intent, a release or a denied attempt is not a contain that did its work.
      expect(sweepsOverdue(view([event({ event_id: 'i', phase: 'intent', at: '2026-11-28T01:45:00.000000Z', sessions_found: 1 }), first]), now('2026-11-28T01:31:00Z'))).toBe(true);
    });

    it('says in the state card that a sweep never reported, on the evidence of the contain’s own event', () => {
      const began = '2026-11-28T01:00:00.000000Z';
      const at = (minutes: number) => Date.parse(began) + minutes * 60_000;
      const contain: AuditEvent = {
        event_id: 'c1', request_id: 'r1', at: began, phase: 'result', action: 'contain', outcome: 'allowed', reason: '', actor_label: 'sam@example.com', sessions_found: 2,
      };
      const lost = { state: 'contained', partial: false, sweeps: { scheduled: 2, done: 0 }, quiet_at: null, contained_at: began, events: [contain] };
      const time = (iso: string) => iso;
      expect(SWEEPS_OVERDUE_NOTE).toBe(
        'A background sweep has still not reported 30 minutes after its contain, and none confirmed that no session is still running.',
      );
      expect(sessionsStatus(lost, time, at(29)).overdue).toBe(false);
      expect(sessionsStatus(lost, time, at(30))).toMatchObject({ overdue: true, unconfirmed: false, partial: false, sweeps: 'Background sweeps: 0 of 2 done.' });
      // Every sweep reported: that is the other note. Quiet: neither.
      expect(sessionsStatus({ ...lost, sweeps: { scheduled: 2, done: 2 } }, time, at(90))).toMatchObject({ overdue: false, unconfirmed: true });
      expect(sessionsStatus({ ...lost, quiet_at: '2026-11-28T01:03:00Z' }, time, at(90))).toMatchObject({ overdue: false, unconfirmed: false });
      // A role that is not sent the events: the page would count from when the containment began,
      // and a later contain's sweeps could still be due. It says nothing.
      expect(sessionsStatus({ ...lost, events: [] }, time, at(90)).overdue).toBe(false);
      expect(sessionsStatus({ state: 'contained', partial: false, sweeps: { scheduled: 2, done: 0 }, quiet_at: null, contained_at: began }, time, at(90)).overdue).toBe(false);
      // Without a clock nothing is called overdue, and nothing is said about another state.
      expect(sessionsStatus(lost, time).overdue).toBe(false);
      expect(sessionsStatus({ ...lost, state: 'not_contained' }, time, at(90)).overdue).toBe(false);
      expect(tabSrc).toContain('const sessions = sessionsStatus(view, (iso) => formatDate(iso), clock);');
      expect(tabSrc).toContain('{sessions.overdue && <p className="mt-2 text-sm font-medium text-amber-900">{SWEEPS_OVERDUE_NOTE}</p>}');
    });

    it('says in the confirmation when the contain can come too soon, and only then', () => {
      const began = '2026-11-28T01:00:00.000000Z';
      const at = (minutes: number) => Date.parse(began) + minutes * 60_000;
      const contained = { state: 'contained', partial: true, quiet_at: null, contained_at: began };
      expect(REPEAT_AFTER_SECONDS).toBe(900);
      expect(REPEAT_TOO_SOON_CAVEAT).toBe(
        'If the last contain was less than about 15 minutes ago, or one of its background sweeps is still running, nothing more is done and the answer says when to ask again.',
      );
      // A sweep can still be running: the API would answer at once.
      expect(repeatMayComeTooSoon({ ...contained, sweeps: { scheduled: 3, done: 1 } }, at(20))).toBe(true);
      // Every sweep has reported, but the contain is less than the pause old.
      expect(repeatMayComeTooSoon({ ...contained, sweeps: { scheduled: 3, done: 3 } }, at(14))).toBe(true);
      // Every sweep has reported and the pause is over: the contain does its work.
      expect(repeatMayComeTooSoon({ ...contained, sweeps: { scheduled: 3, done: 3 } }, at(15))).toBe(false);
      // A sweep that never reported is given up after half an hour: the contain does its work.
      expect(repeatMayComeTooSoon({ ...contained, sweeps: { scheduled: 3, done: 1 } }, at(29))).toBe(true);
      expect(repeatMayComeTooSoon({ ...contained, sweeps: { scheduled: 3, done: 1 } }, at(30))).toBe(false);
      // A containment without sweeps has no pause: containing again is the only way on.
      expect(repeatMayComeTooSoon({ ...contained, sweeps: { scheduled: 0, done: 0 } }, at(1))).toBe(false);
      expect(repeatMayComeTooSoon({ ...contained }, at(1))).toBe(false);
      // The pause is counted from the newest contain that did its work.
      const worked: AuditEvent = {
        event_id: 'c2', request_id: 'r2', at: '2026-11-28T01:40:00.000000Z', phase: 'result', action: 'contain', outcome: 'unchanged', reason: '', actor_label: 'sam@example.com', sessions_found: 0,
      };
      expect(repeatMayComeTooSoon({ ...contained, sweeps: { scheduled: 5, done: 5 }, events: [worked] }, at(50))).toBe(true);
      expect(repeatMayComeTooSoon({ ...contained, sweeps: { scheduled: 5, done: 5 }, events: [worked] }, at(55))).toBe(false);
      // What the page cannot tell, it does not rule out: no clock, or no time to count from.
      expect(repeatMayComeTooSoon({ ...contained, sweeps: { scheduled: 3, done: 3 } }, 0)).toBe(true);
      expect(repeatMayComeTooSoon({ ...contained, contained_at: null, sweeps: { scheduled: 3, done: 3 } }, at(90))).toBe(true);
      // Nothing to say about an agent that is not contained, or without a view.
      expect(repeatMayComeTooSoon({ ...contained, state: 'not_contained', sweeps: { scheduled: 3, done: 1 } }, at(1))).toBe(false);
      expect(repeatMayComeTooSoon(null, at(1))).toBe(false);
      // The tab says it in the confirmation of the repeat only, and reads the clock when that opens.
      expect(tabSrc).toContain("const tooSoonCaveat = confirming === 'repeat' && repeatMayComeTooSoon(view, clock);");
      expect(tabSrc).toContain('{tooSoonCaveat && <p id="repeat-too-soon" className="text-sm text-slate-800 mt-2">{REPEAT_TOO_SOON_CAVEAT}</p>}');
      expect(tabSrc).toContain("aria-describedby={tooSoonCaveat ? 'containment-reason-hint repeat-too-soon' : 'containment-reason-hint'}");
      expect(tabSrc).toMatch(/const open = \(action: Confirming\) => \{[^}]*setClock\(Date\.now\(\)\);/);
    });

    it('does not offer it when nothing suggests that a session is left', () => {
      expect(offeredContainment({ state: 'contained', partial: false }, both).repeat).toBe(false);
      // A clean contain whose sweeps are still to run.
      expect(offeredContainment({ state: 'contained', partial: false, sweeps: { scheduled: 2, done: 1 } }, both).repeat).toBe(false);
      // Once a sweep has confirmed quiet, a partial contain is no longer a reason.
      expect(offeredContainment({ ...left, quiet_at: '2026-11-28T01:30:00Z' }, both).repeat).toBe(false);
      expect(offeredContainment({ ...left, enabled: false }, both).repeat).toBe(false);
      expect(offeredContainment({ ...left, state: 'not_contained' }, both).repeat).toBe(false);
    });
  });
});

describe('background sweeps', () => {
  const at = (iso: string) => `<${iso}>`;
  const held = (over: Partial<ContainmentView> = {}): ContainmentView => ({ agent_id: 'a', state: 'contained', ...over });

  it('counts whole sweeps, never more done than scheduled, and nothing from a malformed answer', () => {
    expect(sweepCounts(held({ sweeps: { scheduled: 2, done: 1 } }))).toEqual({ scheduled: 2, done: 1 });
    expect(sweepCounts(held({ sweeps: { scheduled: 2, done: 5 } }))).toEqual({ scheduled: 2, done: 2 });
    expect(sweepCounts(held({ sweeps: { scheduled: -1, done: 1 } }))).toEqual({ scheduled: 0, done: 0 });
    expect(sweepCounts(held({ sweeps: null }))).toEqual({ scheduled: 0, done: 0 });
    expect(sweepCounts(held())).toEqual({ scheduled: 0, done: 0 });
    expect(sweepCounts(null)).toEqual({ scheduled: 0, done: 0 });
    expect(sweepCounts(held({ sweeps: { scheduled: Number.NaN, done: 1 } }))).toEqual({ scheduled: 0, done: 0 });
  });

  it('is pending only while a sweep of a contained agent has not run', () => {
    expect(sweepsPending(held({ sweeps: { scheduled: 2, done: 1 } }))).toBe(true);
    expect(sweepsPending(held({ sweeps: { scheduled: 2, done: 2 } }))).toBe(false);
    expect(sweepsPending(held({ sweeps: { scheduled: 0, done: 0 } }))).toBe(false);
    // After a release nothing is watched: a late sweep stops nothing.
    expect(sweepsPending(held({ state: 'not_contained', sweeps: { scheduled: 2, done: 0 } }))).toBe(false);
    expect(sweepsPending(held({ state: 'unknown', sweeps: { scheduled: 2, done: 0 } }))).toBe(false);
    expect(sweepsPending(null)).toBe(false);
  });

  it('reads the state again every 20 seconds, for at most 40 minutes', () => {
    expect(SWEEP_POLL_SECONDS).toBe(20);
    // The last sweep starts 15 minutes after the contain and can run for 15 more.
    expect(SWEEP_POLL_SECONDS * SWEEP_POLL_LIMIT).toBeGreaterThanOrEqual(30 * 60);
  });

  it('says how many sweeps have run', () => {
    expect(sessionsStatus(held({ sweeps: { scheduled: 2, done: 1 } }), at)).toEqual({
      quiet: null,
      partial: false,
      sweeps: 'Background sweeps: 1 of 2 done.',
      unconfirmed: false,
      overdue: false,
    });
    expect(sessionsStatus(held({ sweeps: { scheduled: 0, done: 0 } }), at).sweeps).toBeNull();
  });

  it('says since when no session is running, in place of the partial warning', () => {
    const status = sessionsStatus(held({ partial: true, sweeps: { scheduled: 3, done: 2 }, quiet_at: '2026-11-28T01:32:10Z' }), at);
    expect(status.quiet).toBe('No running session since <2026-11-28T01:32:10Z>. Every session the portal could find has ended or was stopped.');
    expect(status.partial).toBe(false);
    expect(status.unconfirmed).toBe(false);
    expect(status.sweeps).toBe('Background sweeps: 2 of 3 done.');
  });

  it('keeps the partial warning until a sweep has confirmed that no session is running', () => {
    expect(sessionsStatus(held({ partial: true }), at)).toEqual({ quiet: null, partial: true, sweeps: null, unconfirmed: false, overdue: false });
    expect(sessionsStatus(held({ partial: true, sweeps: { scheduled: 3, done: 1 } }), at).partial).toBe(true);
    expect(sessionsStatus(held({ partial: true, quiet_at: '  ' }), at).partial).toBe(true);
  });

  it('says so when every sweep has run and none confirmed that no session is running', () => {
    expect(sessionsStatus(held({ sweeps: { scheduled: 2, done: 2 } }), at).unconfirmed).toBe(true);
    expect(sessionsStatus(held({ sweeps: { scheduled: 2, done: 1 } }), at).unconfirmed).toBe(false);
    expect(sessionsStatus(held({ sweeps: { scheduled: 2, done: 2 }, quiet_at: '2026-11-28T01:32:10Z' }), at).unconfirmed).toBe(false);
  });

  it('says nothing about sessions for an agent that is not contained', () => {
    const nothing = { quiet: null, partial: false, sweeps: null, unconfirmed: false, overdue: false };
    expect(sessionsStatus(held({ state: 'not_contained', partial: true, sweeps: { scheduled: 2, done: 2 }, quiet_at: 'x' }), at)).toEqual(nothing);
    expect(sessionsStatus(held({ state: 'unknown', partial: true }), at)).toEqual(nothing);
    expect(sessionsStatus(null, at)).toEqual(nothing);
  });

  it('knows when sessions may be left', () => {
    // No queue: the request was partial and nothing follows it.
    expect(sessionsMayRemain(held({ partial: true }))).toBe(true);
    // Every sweep ran without confirming quiet, whether or not the request itself was clean.
    expect(sessionsMayRemain(held({ partial: false, sweeps: { scheduled: 2, done: 2 } }))).toBe(true);
    expect(sessionsMayRemain(held({ partial: true, sweeps: { scheduled: 3, done: 3 } }))).toBe(true);
    // A partial contain is a reason at once, also while a sweep is still to run.
    expect(sessionsMayRemain(held({ partial: true, sweeps: { scheduled: 3, done: 2 } }))).toBe(true);
    // A clean contain with a sweep still to run is not.
    expect(sessionsMayRemain(held({ partial: false, sweeps: { scheduled: 2, done: 1 } }))).toBe(false);
    // Confirmed quiet, a clean request with no sweeps, and an agent that is not contained.
    expect(sessionsMayRemain(held({ partial: true, sweeps: { scheduled: 2, done: 2 }, quiet_at: '2026-11-28T01:32:10Z' }))).toBe(false);
    expect(sessionsMayRemain(held({ partial: false }))).toBe(false);
    expect(sessionsMayRemain(held({ state: 'not_contained', partial: true }))).toBe(false);
    expect(sessionsMayRemain(null)).toBe(false);
  });

  it('says what stopping the remaining sessions does, and mentions sweeps only where there are any', () => {
    expect(repeatEffects(false)).toEqual([
      'The agent stays contained. Its policy is not changed.',
      'Sessions that the portal can find and that are still running are stopped.',
      'Nothing is deleted, and who may release the agent does not change.',
    ]);
    expect(repeatEffects(true)[2]).toBe('Background sweeps are scheduled again.');
    expect(repeatEffects(true)).toHaveLength(4);
  });

  it('knows from a result that the sweeps could not be scheduled, which the view does not say afterwards', () => {
    const step = (status: string) => ({ id: 'background', label: 'Stop remaining sessions in the background', status });
    expect(sweepsNotScheduled({ steps: [step('failed')] })).toBe(true);
    expect(sweepsNotScheduled({ steps: [step('scheduled')] })).toBe(false);
    // Without a sweep queue the step does not exist.
    expect(sweepsNotScheduled({ steps: [{ id: 'sessions', label: 'x', status: 'failed' }] })).toBe(false);
    expect(sweepsNotScheduled({})).toBe(false);
    expect(sweepsNotScheduled(null)).toBe(false);
    // The page offers the contain again after such a result, to a caller who may contain.
    expect(tabSrc).toContain(
      "last?.action === 'contain' && state === 'contained' && who.canContain && view.enabled !== false && sweepsNotScheduled(last.result);",
    );
  });
});

describe('each sweep of the containment that holds', () => {
  const sweepEvent = (over: Partial<AuditEvent>): AuditEvent => ({
    event_id: 'e',
    request_id: 'req-1',
    at: '2026-11-28T01:02:05.000000Z',
    phase: 'result',
    action: 'sweep',
    outcome: 'allowed',
    reason: '',
    actor_label: 'Agent Factory Portal (background sweep)',
    actor_role: 'system',
    ...over,
  });
  const view = (events: AuditEvent[], over: Partial<ContainmentView> = {}): ContainmentView => ({
    agent_id: 'a',
    state: 'contained',
    contained_at: '2026-11-28T01:00:00.000000Z',
    events,
    ...over,
  });

  it('lists them oldest first, with what each checked, stopped, found ended and failed', () => {
    const lines = sweepLines(
      view([
        sweepEvent({ event_id: 's2', sweep: 2, at: '2026-11-28T01:02:05.000000Z', sessions_found: 3, sessions_stopped: 0, sessions_not_active: 3, sessions_failed: 0 }),
        sweepEvent({ event_id: 's1', sweep: 1, at: '2026-11-28T01:00:04.000000Z', outcome: 'failed', sessions_found: 3, sessions_stopped: 2, sessions_not_active: 0, sessions_failed: 1 }),
        // The contain itself is not a sweep.
        { ...sweepEvent({ event_id: 'c', action: 'contain', at: '2026-11-28T01:00:00.000000Z' }) },
      ]),
    );
    expect(lines).toEqual([
      { key: 's1', label: 'Sweep 1', at: '2026-11-28T01:00:04.000000Z', counts: '3 checked, 2 stopped, 0 already ended, 1 failed', outcome: 'Incomplete' },
      { key: 's2', label: 'Sweep 2', at: '2026-11-28T01:02:05.000000Z', counts: '3 checked, 0 stopped, 3 already ended, 0 failed', outcome: 'Complete' },
    ]);
  });

  it('leaves out the sweeps of an earlier containment, and says nothing for an agent that is not contained', () => {
    const earlier = sweepEvent({ event_id: 'old', sweep: 3, at: '2026-11-27T20:15:00.000000Z', outcome: 'failed' });
    expect(sweepLines(view([earlier]))).toEqual([]);
    expect(sweepLines(view([sweepEvent({})], { state: 'not_contained' }))).toEqual([]);
    // Contained by other means: no containment of the portal's whose sweeps these could be.
    expect(sweepLines(view([sweepEvent({})], { contained_at: null }))).toEqual([]);
    expect(sweepLines(null)).toEqual([]);
  });

  it('gives no counts for a sweep that ended before it listed any session, and no number when there is none', () => {
    const [line] = sweepLines(view([sweepEvent({ event_id: 's', outcome: 'skipped', sweep: null, sessions_found: null })]));
    expect(line).toMatchObject({ label: 'Sweep', counts: '', outcome: 'Skipped' });
  });

  it('words a sweep’s outcome as complete or not: it is not a decision', () => {
    expect(sweepOutcomeLabel('allowed')).toBe('Complete');
    expect(sweepOutcomeLabel('failed')).toBe('Incomplete');
    expect(sweepOutcomeLabel('skipped')).toBe('Skipped');
    expect(sweepOutcomeLabel('paused')).toBe('paused');
    expect(sweepOutcomeLabel('')).toBe('Unknown');
  });

  it('knows that the newest sweep of this containment failed, which is a reason to sweep again', () => {
    const failed = sweepEvent({ event_id: 's2', sweep: 2, outcome: 'failed' });
    const clean = sweepEvent({ event_id: 's1', sweep: 1, at: '2026-11-28T01:00:04.000000Z' });
    expect(lastSweepFailed(view([failed, clean]))).toBe(true);
    expect(lastSweepFailed(view([{ ...clean, at: '2026-11-28T01:03:00.000000Z' }, failed]))).toBe(false);
    // A failed sweep of an earlier containment is not this one's.
    expect(lastSweepFailed(view([{ ...failed, at: '2026-11-27T20:15:00.000000Z' }]))).toBe(false);
    expect(lastSweepFailed(view([]))).toBe(false);
    expect(lastSweepFailed(null)).toBe(false);
    // With a clean contain, that failure alone is a reason for the remedy, whether or not another
    // sweep is still to run.
    const cleanContain = { ...view([failed, clean]), partial: false, sweeps: { scheduled: 2, done: 1 }, quiet_at: null };
    expect(sessionsMayRemain(cleanContain)).toBe(true);
    expect(offeredContainment(cleanContain, { canContain: true, canRelease: false }).repeat).toBe(true);
    expect(offeredContainment({ ...cleanContain, sweeps: { scheduled: 2, done: 2 } }, { canContain: true, canRelease: false }).repeat).toBe(true);
  });
});

describe('the incident record', () => {
  const responder = { canContain: true, canRelease: false };
  const reader = { canContain: false, canRelease: false };

  it('is shown to a role that can contain or release', () => {
    expect(showsIncidentRecord({ events: [] }, responder)).toBe(true);
    expect(showsIncidentRecord({ events: [] }, { canContain: false, canRelease: true })).toBe(true);
  });

  it('is not shown to another role, which the API sends none of it', () => {
    expect(showsIncidentRecord({ events: [], contained_by_label: null, reason: null }, reader)).toBe(false);
    expect(showsIncidentRecord({}, reader)).toBe(false);
    expect(showsIncidentRecord(null, reader)).toBe(false);
    expect(INCIDENT_RECORD_NOTE).toBe('Who contained this agent, why, and the history are shown to the security, platform and SRE roles.');
  });

  it('shows whatever the API did send', () => {
    expect(showsIncidentRecord({ events: [{ event_id: 'e' } as AuditEvent] }, reader)).toBe(true);
    expect(showsIncidentRecord({ contained_by_label: 'sam@example.com' }, reader)).toBe(true);
    expect(showsIncidentRecord({ reason: 'Leaking data.' }, reader)).toBe(true);
  });
});

describe('stateCard', () => {
  it('describes the two known states in fixed words', () => {
    expect(stateCard({ state: 'contained' })).toMatchObject({
      heading: 'Contained',
      body: 'Invocations of this agent are denied. Nothing was deleted, and it can be released.',
    });
    expect(stateCard({ state: 'not_contained' })).toMatchObject({ heading: 'Not contained', body: 'This agent can be invoked.', note: null });
  });

  it('adds what the API says about a state it knows, as sent', () => {
    // A statement that carries the portal's identifier but does not deny invocation: not contained.
    const decoy = 'A statement with the portal’s identifier is in the Runtime’s resource policy but does not deny invocation; contain the agent to replace it.';
    expect(stateCard({ state: 'not_contained', detail: decoy })).toMatchObject({ heading: 'Not contained', body: 'This agent can be invoked.', note: decoy });
    const holder = 'Who contained the agent could not be established: the Runtime’s history holds more than 2000 events since its last contain or release.';
    expect(stateCard({ state: 'contained', detail: ` ${holder} ` })).toMatchObject({ heading: 'Contained', note: holder });
    expect(stateCard({ state: 'contained', detail: ' ' }).note).toBeNull();
    // For an unknown state the sentence is the body, not a second note.
    expect(stateCard({ state: 'unknown', runtime_arn: RUNTIME_ARN, detail: 'The policy could not be read.' }).note).toBeNull();
    expect(stateCard({ state: 'unknown', runtime_arn: null, detail: 'This agent has no Runtime.' }).note).toBeNull();
  });

  it('gives the API’s reason for an unknown state, and never calls it not contained', () => {
    const noReader = 'There is no reader in this agent’s account, so its containment state cannot be read.';
    expect(stateCard({ state: 'unknown', runtime_arn: RUNTIME_ARN, detail: noReader })).toMatchObject({
      heading: 'Containment state unknown',
      body: `${noReader} Whether the agent can be invoked is therefore not known.`,
    });
    expect(stateCard({ state: 'unknown' }).body).toBe(
      'The runtime’s resource policy could not be read. Whether the agent can be invoked is therefore not known.',
    );
    expect(stateCard({ state: 'something-new', detail: ' ' }).heading).toBe('Containment state unknown');
  });

  it('says there is nothing to contain when the agent has no runtime', () => {
    expect(stateCard({ state: 'unknown', runtime_arn: null, detail: 'This agent has no Runtime.' })).toMatchObject({
      heading: 'No runtime to contain',
      body: 'This agent has no Runtime.',
    });
    expect(stateCard({ state: 'unknown', runtime_arn: '' }).body).toBe('This agent has no runtime.');
    expect(hasNoRuntime({ runtime_arn: null })).toBe(true);
    expect(hasNoRuntime({ runtime_arn: RUNTIME_ARN })).toBe(false);
    expect(hasNoRuntime({})).toBe(false);
    expect(hasNoRuntime(null)).toBe(false);
  });
});

describe('partial results', () => {
  const contained = (over: Partial<ContainmentResult> = {}): ContainmentResult => ({
    action: 'contain',
    outcome: 'allowed',
    request_id: 'req-1',
    state: 'contained',
    changed: true,
    partial: false,
    enforcement_delay_seconds: 90,
    steps: [
      { id: 'policy', label: 'Deny invocation of the Runtime', status: 'done', detail: null },
      { id: 'verify', label: 'Verify the policy', status: 'done', detail: null },
      { id: 'sessions', label: 'Stop the Runtime’s running sessions', status: 'done', detail: '3 sessions stopped.' },
    ],
    sessions: { discovery: 'ok', found: 3, stopped: 3, not_active: 0, failed: 0, not_attempted: 0 },
    ...over,
  });

  it('is complete when the API says so and every step is done, unchanged or skipped', () => {
    expect(isPartial(contained())).toBe(false);
    expect(isPartial({ steps: [{ id: 'policy', label: 'x', status: 'unchanged' }, { id: 'sessions', label: 'y', status: 'skipped' }] })).toBe(false);
    expect(isPartial(null)).toBe(false);
  });

  it('is partial when the API says so, a step is partial or failed, or a session was not stopped', () => {
    expect(isPartial(contained({ partial: true }))).toBe(true);
    expect(isPartial({ steps: [{ id: 'sessions', label: 'x', status: 'partial' }] })).toBe(true);
    expect(isPartial({ steps: [{ id: 'sessions', label: 'x', status: 'failed' }] })).toBe(true);
    expect(isPartial({ sessions: { discovery: 'ok', found: 3, stopped: 2, failed: 1 } })).toBe(true);
    expect(isPartial({ sessions: { discovery: 'ok', found: 300, stopped: 200, not_attempted: 100 } })).toBe(true);
    expect(isPartial({ sessions: { discovery: 'The telemetry query was refused.' } })).toBe(true);
    // One source of session ids could not be read: the counts stand, the discovery was not clean.
    expect(isPartial({ sessions: { discovery: 'ok; spans could not be queried (AccessDeniedException)', found: 2, stopped: 2 } })).toBe(true);
  });

  it('reads the scheduled background sweeps as done for the request, not as a partial result', () => {
    const background = { id: 'background', label: 'Stop remaining sessions in the background', status: 'scheduled', detail: 'Later sweeps are scheduled.' };
    const withSweeps = contained({ steps: [...(contained().steps ?? []), background], sweeps_scheduled_in_seconds: [120, 900] });
    expect(stepStatusView('scheduled')).toMatchObject({ label: 'Scheduled', ok: true });
    expect(isPartial(withSweeps)).toBe(false);
    expect(incompleteWords(withSweeps)).toBe('');
    expect(resultHeadline('contain', withSweeps)).toBe('Contained. Invocations are blocked within about 90 seconds.');
  });

  it('names what did not complete: the sessions, the scheduling of the sweeps, or both', () => {
    const steps = contained().steps ?? [];
    const failed = { id: 'background', label: 'Stop remaining sessions in the background', status: 'failed', detail: 'Background sweeps could not be scheduled.' };
    const sweepsOnly = contained({ partial: true, steps: [...steps, failed] });
    expect(incompleteWords(sweepsOnly)).toBe('the background sweeps could not all be scheduled');
    expect(resultHeadline('contain', sweepsOnly)).toBe(
      'Contained, but the background sweeps could not all be scheduled. Invocations are blocked within about 90 seconds.',
    );
    const sessionsPartial = [...steps.slice(0, 2), { id: 'sessions', label: 'Stop the Runtime’s running sessions', status: 'partial', detail: '2 of 3 stopped.' }];
    expect(incompleteWords(contained({ partial: true, steps: sessionsPartial }))).toBe('not every running session was stopped');
    expect(incompleteWords(contained({ partial: true, steps: [...sessionsPartial, failed] }))).toBe(
      'not every running session was stopped and the background sweeps could not all be scheduled',
    );
    expect(resultHeadline('contain', contained({ outcome: 'unchanged', changed: false, partial: true, steps: [...steps, failed] }))).toBe(
      'The agent was already contained, and its policy was not changed. The background sweeps could not all be scheduled.',
    );
    // A step this page does not know, not done: said without guessing which.
    expect(incompleteWords({ steps: [{ id: 'x', label: 'x', status: 'timed_out' }] })).toBe('a step did not complete');
    expect(incompleteWords(contained())).toBe('');
    expect(incompleteWords(null)).toBe('');
  });

  it('counts an unrecognised step status as not done and shows it as recorded', () => {
    expect(stepStatusView('timed_out')).toMatchObject({ label: 'timed_out', ok: false });
    expect(isPartial({ steps: [{ id: 'x', label: 'x', status: 'timed_out' }] })).toBe(true);
    expect(stepStatusView('done').label).toBe('Done');
    expect(stepStatusView('partial').label).toBe('Partly done');
    expect(stepStatusView(null)).toMatchObject({ label: 'Unknown', ok: false });
  });

  it('says how long a contain can take, from the result, never "now"', () => {
    expect(resultHeadline('contain', contained())).toBe('Contained. Invocations are blocked within about 90 seconds.');
    expect(resultHeadline('contain', contained({ enforcement_delay_seconds: 45 }))).toBe('Contained. Invocations are blocked within about 45 seconds.');
    // Without a number from the API the measured value is used.
    expect(resultHeadline('contain', contained({ enforcement_delay_seconds: null }))).toMatch(/within about 90 seconds/);
  });

  it('says that after a release some calls can still be refused, and for how long', () => {
    const released = { ...contained(), action: 'release', state: 'not_contained', sessions: null, enforcement_delay_seconds: 300 };
    expect(resultHeadline('release', released)).toBe('Released. Some calls can still be refused for about 5 minutes.');
    expect(resultHeadline('release', { ...released, enforcement_delay_seconds: undefined })).toBe('Released. Some calls can still be refused for about 5 minutes.');
    expect(resultHeadline('release', { ...released, enforcement_delay_seconds: 60 })).toBe('Released. Some calls can still be refused for about 60 seconds.');
  });

  it('words a delay in seconds below two minutes and in minutes from there', () => {
    expect(aboutDuration(90, 1)).toBe('about 90 seconds');
    expect(aboutDuration(119, 1)).toBe('about 119 seconds');
    expect(aboutDuration(120, 1)).toBe('about 2 minutes');
    expect(aboutDuration(300, 1)).toBe('about 5 minutes');
    expect(aboutDuration(null, CONTAIN_DELAY_SECONDS)).toBe('about 90 seconds');
    expect(aboutDuration(0, RELEASE_DELAY_SECONDS)).toBe('about 5 minutes');
    expect(aboutDuration(Number.NaN, RELEASE_DELAY_SECONDS)).toBe('about 5 minutes');
  });

  it('says so in the headline when not every session was stopped', () => {
    expect(resultHeadline('contain', contained({ partial: true }))).toBe(
      'Contained, but not every running session was stopped. Invocations are blocked within about 90 seconds.',
    );
  });

  it('does not claim containment or release when the verified state says otherwise', () => {
    expect(resultHeadline('contain', contained({ state: 'not_contained' }))).toBe('The agent could not be confirmed as contained.');
    expect(resultHeadline('release', { ...contained(), action: 'release', state: 'contained' })).toBe('The agent could not be confirmed as released.');
  });

  it('reports a repeated contain as leaving the policy alone, without claiming that nothing happened', () => {
    // A repeated contain does not touch the policy but still stops the sessions it finds.
    expect(resultHeadline('contain', contained({ outcome: 'unchanged', changed: false }))).toBe(
      'The agent was already contained. Its policy was not changed.',
    );
    expect(resultHeadline('contain', contained({ outcome: 'unchanged', changed: false, partial: true }))).toBe(
      'The agent was already contained, and its policy was not changed. Not every running session was stopped.',
    );
    expect(resultHeadline('release', { ...contained(), action: 'release', outcome: 'unchanged', state: 'not_contained', sessions: null, steps: [] })).toBe(
      'The agent was not contained. Nothing was changed.',
    );
  });

  it('labels the contain sent again as a sweep of the sessions, not as a containment', () => {
    const again = contained({ outcome: 'unchanged', changed: false });
    expect(resultHeadline('contain', again, true)).toBe('Sessions swept again.');
    expect(resultHeadline('contain', contained({ outcome: 'unchanged', changed: false, partial: true }), true)).toBe(
      'Sessions swept again. Not every running session was stopped.',
    );
    // The same answer to an ordinary contain keeps its own words.
    expect(resultHeadline('contain', again)).toBe('The agent was already contained. Its policy was not changed.');
    // If the agent had been released meanwhile, it was contained: the headline says that.
    expect(resultHeadline('contain', contained(), true)).toBe('Contained. Invocations are blocked within about 90 seconds.');
    // An answer that carries no session result does not claim a sweep.
    expect(resultHeadline('contain', contained({ outcome: 'unchanged', changed: false, sessions: null }), true)).toBe(
      'The agent was already contained. Its policy was not changed.',
    );
  });

  it('says that nothing more was done when the API answers that the contain came too soon', () => {
    const steps = [
      { id: 'policy', label: 'Deny invocation', status: 'unchanged', detail: 'The Runtime was already contained.' },
      { id: 'verify', label: 'Read the policy back', status: 'done', detail: null },
      { id: 'sessions', label: 'Stop the sessions', status: 'skipped', detail: 'The background sweeps of this containment are still running, so nothing more was done.' },
    ];
    const tooSoon = contained({ outcome: 'unchanged', changed: false, sessions: null, steps, retry_after_seconds: 612 });
    expect(retryAfterSeconds(tooSoon)).toBe(612);
    expect(isPartial(tooSoon)).toBe(false);
    // Whether it was asked as a contain or as "Stop remaining sessions": no sweep is claimed.
    expect(resultHeadline('contain', tooSoon)).toBe('The agent was already contained. Nothing more was done.');
    expect(resultHeadline('contain', tooSoon, true)).toBe('The agent was already contained. Nothing more was done.');
    expect(retryNote(612)).toBe('Sessions can be swept again in about 10 minutes.');
    expect(retryNote(45)).toBe('Sessions can be swept again in about 45 seconds.');
    // Absent, zero or malformed: the contain did its work.
    expect(retryAfterSeconds(contained())).toBe(0);
    expect(retryAfterSeconds({ retry_after_seconds: 0 })).toBe(0);
    expect(retryAfterSeconds({ retry_after_seconds: null })).toBe(0);
    expect(retryAfterSeconds({ retry_after_seconds: Number.NaN })).toBe(0);
    expect(retryAfterSeconds({ retry_after_seconds: 0.2 })).toBe(1);
    expect(retryAfterSeconds(null)).toBe(0);
  });

  it('names only the session sources the API names', () => {
    // Traces are a source a cell opts in to: when it is not asked, it is not shown as zero.
    expect(sessionsText({ discovery: 'ok', found: 3, stopped: 3, sources: { log_streams: 3 } })).toBe('3 sessions found (3 in logs), 3 stopped.');
    expect(sessionsText({ discovery: 'ok', found: 3, stopped: 3, sources: { spans: 0, log_streams: 3 } })).toBe(
      '3 sessions found (0 in traces, 3 in logs), 3 stopped.',
    );
    expect(sessionsText({ discovery: 'ok', found: 1, stopped: 1, sources: {} })).toBe('1 session found, 1 stopped.');
    expect(sessionsText({ discovery: 'ok', found: 1, stopped: 1, sources: null })).toBe('1 session found, 1 stopped.');
    const text = sessionsText({ discovery: 'ok', found: 2, stopped: 2, sources: { log_streams: 2 } }) ?? '';
    expect(text).not.toMatch(/traces|undefined|NaN/);
  });

  it('puts the session counts in one sentence', () => {
    expect(sessionsText({ discovery: 'ok', found: 0 })).toBe('No recent session was found to stop.');
    expect(sessionsText({ discovery: 'ok', found: 3, stopped: 1, not_active: 1, failed: 1 })).toBe(
      '3 sessions found, 1 stopped, 1 already ended, 1 could not be stopped.',
    );
    expect(sessionsText({ discovery: 'ok', found: 1, stopped: 1 })).toBe('1 session found, 1 stopped.');
    expect(sessionsText(null)).toBeNull();
    expect(sessionsText(undefined)).toBeNull();
  });

  it('says where the sessions were found and which errors stopped a stop', () => {
    expect(
      sessionsText({
        discovery: 'ok',
        sources: { spans: 2, log_streams: 3 },
        found: 3,
        stopped: 2,
        not_active: 0,
        failed: 1,
        not_attempted: 0,
        stop_errors: ['ThrottlingException'],
      }),
    ).toBe('3 sessions found (2 in traces, 3 in logs), 2 stopped, 1 could not be stopped (ThrottlingException).');
    expect(sessionsText({ discovery: 'ok', found: 250, stopped: 200, not_attempted: 50 })).toBe(
      '250 sessions found, 200 stopped, 50 not tried before the time limit.',
    );
  });

  it('keeps the counts and names what was incomplete when one source could not be read', () => {
    expect(
      sessionsText({ discovery: 'ok; spans could not be queried (AccessDeniedException)', sources: { spans: 0, log_streams: 2 }, found: 2, stopped: 2 }),
    ).toBe('2 sessions found (0 in traces, 2 in logs), 2 stopped. Session discovery was incomplete: spans could not be queried (AccessDeniedException).');
    expect(sessionsText({ discovery: 'ok; endpoints could not be listed (ThrottlingException), only DEFAULT was checked', found: 0 })).toBe(
      'No recent session was found to stop. Session discovery was incomplete: endpoints could not be listed (ThrottlingException), only DEFAULT was checked.',
    );
  });

  it('says that nothing was stopped when the sessions could not be listed or stopped', () => {
    expect(sessionsText({ discovery: 'sessions could not be listed (spans could not be queried (X); log streams could not be listed (Y))' })).toBe(
      'Running sessions were not stopped: sessions could not be listed (spans could not be queried (X); log streams could not be listed (Y)).',
    );
    expect(sessionsText({ discovery: 'The telemetry query was refused.' })).toBe('Running sessions were not stopped: The telemetry query was refused.');
    expect(sessionsText({ discovery: '' })).toBe('Running sessions were not stopped: no reason was given.');
    // A word that merely starts with "ok" is not the clean marker.
    expect(sessionsText({ discovery: 'okay-ish' })).toMatch(/^Running sessions were not stopped/);
  });
});

describe('splitReason', () => {
  it('separates what the person wrote from what was done', () => {
    expect(
      splitReason('Returning other customers’ orders. [Invocation of the Runtime is denied (statement written and verified; enforced within about 90 seconds). 2 of 2 recent session(s) stopped.]'),
    ).toEqual({
      reason: 'Returning other customers’ orders.',
      done: 'Invocation of the Runtime is denied (statement written and verified; enforced within about 90 seconds). 2 of 2 recent session(s) stopped.',
    });
  });

  it('splits at the first bracket only, so a bracket inside what was done stays', () => {
    expect(splitReason('Why [done [nested] more]')).toEqual({ reason: 'Why', done: 'done [nested] more' });
  });

  it('leaves a reason without a bracketed part whole', () => {
    expect(splitReason('The Runtime was already contained; its policy was not changed.')).toEqual({
      reason: 'The Runtime was already contained; its policy was not changed.',
      done: '',
    });
    expect(splitReason('Half [open')).toEqual({ reason: 'Half [open', done: '' });
    expect(splitReason(null)).toEqual({ reason: '', done: '' });
    expect(splitReason('  ')).toEqual({ reason: '', done: '' });
  });
});

describe('stepsFromFailure', () => {
  it('reads the steps a failed request carries', () => {
    expect(
      stepsFromFailure({ detail: 'x', steps: [{ id: 'policy', label: 'Deny invocation', status: 'failed', detail: 'AccessDeniedException. Nothing was changed.' }] }),
    ).toEqual([{ id: 'policy', label: 'Deny invocation', status: 'failed', detail: 'AccessDeniedException. Nothing was changed.' }]);
  });

  it('never throws on a body without usable steps', () => {
    for (const body of [null, undefined, 'text', {}, { steps: 'none' }, { steps: [null, 7] }]) {
      expect(stepsFromFailure(body)).toEqual([]);
    }
    expect(stepsFromFailure({ steps: [{ status: 'failed' }] })).toEqual([{ id: 'step-0', label: 'Step', status: 'failed', detail: null }]);
  });
});

describe('wording', () => {
  it('states the four effects of containing an agent before the user confirms', () => {
    const effects = containEffects(90);
    const text = effects.join(' ');
    expect(effects).toHaveLength(4);
    // The deny spreads host by host: the page does not promise that nothing gets through at once.
    expect(effects[0]).toBe('New invocations of this agent are denied. An occasional call can still get through for about 90 seconds.');
    expect(text).toMatch(/running are stopped/);
    expect(text).toMatch(/Nothing is deleted/);
    expect(text).toMatch(/reversible/);
  });

  it('says that a release does not restart sessions and takes longer to apply than a contain', () => {
    expect(releaseEffects(300)).toEqual([
      'The agent can be invoked again. Some calls can still be refused for about 5 minutes while the change spreads.',
      'Sessions that were stopped are not restarted.',
    ]);
    // An older API that sends no release delay: the measured value, not the contain delay.
    expect(releaseEffects(undefined)[0]).toMatch(/about 5 minutes/);
  });

  it('labels history actions, showing an unknown one as recorded', () => {
    expect(eventActionLabel('contain')).toBe('Contain');
    expect(eventActionLabel('release')).toBe('Release');
    expect(eventActionLabel('sweep')).toBe('Background sweep');
    expect(eventActionLabel('escalate')).toBe('escalate');
  });

  it('labels the outcome of a sweep that found its agent released', () => {
    expect(outcomeView('skipped').label).toBe('Skipped');
  });
});

describe('the history of a containment with background sweeps', () => {
  const event = (over: Partial<AuditEvent>): AuditEvent => ({
    event_id: 'e',
    request_id: 'req-1',
    at: '2026-11-28T01:00:00Z',
    phase: 'result',
    action: 'contain',
    outcome: 'allowed',
    reason: '',
    actor_label: 'sam@example.com',
    actor_role: 'security',
    status_before: 'not_contained',
    status_after: 'contained',
    ...over,
  });
  const sweep = (id: string, over: Partial<AuditEvent> = {}) =>
    event({
      event_id: id,
      action: 'sweep',
      actor_label: 'Agent Factory Portal (background sweep)',
      actor_role: 'system',
      status_before: 'contained',
      reason: 'Background sweep 2 found no session of the lookback window.',
      ...over,
    });

  it('gives each sweep a row of its own beside the contain that scheduled it', () => {
    const rows = historyRows([
      sweep('s2', { at: '2026-11-28T01:02:05Z' }),
      event({ event_id: 'r1' }),
      event({ event_id: 'i1', phase: 'intent', at: '2026-11-28T00:59:59Z' }),
    ]);
    expect(rows.map((row) => [row.key, row.action, row.outcome])).toEqual([
      ['s2', 'sweep', 'allowed'],
      ['r1', 'contain', 'allowed'],
    ]);
    expect(rows[0]).toMatchObject({ actor: 'Agent Factory Portal (background sweep)', role: 'system' });
  });

  it('never lets a sweep stand in for the result of its contain', () => {
    // The contain's result event was not written; its sweeps carry the same request id.
    const rows = historyRows([sweep('s2', { at: '2026-11-28T01:02:05Z' }), event({ event_id: 'i1', phase: 'intent' })]);
    expect(rows.map((row) => [row.key, row.action, row.outcome])).toEqual([
      ['s2', 'sweep', 'allowed'],
      ['i1', 'contain', 'incomplete'],
    ]);
  });

  it('shows a skipped sweep as recorded', () => {
    const rows = historyRows([sweep('s3', { outcome: 'skipped', reason: 'Background sweep 3 stopped nothing: the Runtime is no longer contained.' })]);
    expect(rows[0].outcome).toBe('skipped');
    expect(outcomeView(rows[0].outcome).label).toBe('Skipped');
  });
});

describe('the Containment tab', () => {
  it('renders the action buttons only behind what is offered', () => {
    expect(tabSrc).toContain('{offered.contain && (');
    expect(tabSrc).toContain('{offered.release && (');
    expect(tabSrc).toContain('{offerRepeat && !repeatWait && (');
    expect(tabSrc).toContain('const offerRepeat = offered.repeat || retrySweeps;');
    expect(tabSrc).toContain("const who = { canContain: user?.can_contain === true, canRelease: user?.can_release === true };");
  });

  it('shows the effects before the button, and enables the button only once a reason is entered', () => {
    expect(tabSrc.indexOf('effects.map(')).toBeLessThan(tabSrc.indexOf('onClick={() => void run()}'));
    expect(tabSrc).toContain("const hasReason = reason.trim() !== '';");
    expect(tabSrc).toContain('disabled={busy || !hasReason}');
    // Nothing is sent without a reason even if the button were pressed.
    expect(tabSrc).toContain('if (!confirming || !trimmed) return;');
  });

  it('takes the release delay from the view for the release confirmation', () => {
    expect(tabSrc).toContain('releaseEffects(view.release_delay_seconds)');
    expect(tabSrc).toContain('containEffects(view.enforcement_delay_seconds)');
  });

  it('names the agent with its tenant and account in the confirmation', () => {
    expect(tabSrc).toContain('const named = context ? `${agent.name} (${context})` : agent.name;');
    expect(tabSrc).toContain('`Contain ${named}?`');
  });

  it('shows Release as a disabled button with the reason beside it, never hidden, for the person who contained the agent', () => {
    const blocked = tabSrc.slice(tabSrc.indexOf('{offered.releaseBlocked && ('));
    expect(blocked.slice(0, 400)).toContain('disabled aria-describedby="release-unavailable"');
    expect(blocked.slice(0, 500)).toContain('<p id="release-unavailable"');
  });

  it('asks the API nothing for an agent in an account with no reader role, and says so plainly', () => {
    expect(tabSrc).toContain("const noReader = readerState(agent) === 'none';");
    expect(tabSrc).toContain('() => (noReader ? Promise.resolve(null) : containmentApi.get(agent.id))');
    expect(NOT_READABLE).toMatchObject({
      heading: 'Not readable',
      body: 'The portal has no role in this agent’s account, so it cannot read its state or contain it.',
    });
  });

  it('reads the state again after a failure, as the contract requires', () => {
    const catchBlock = tabSrc.slice(tabSrc.indexOf('} catch (err) {'), tabSrc.indexOf('} finally {'));
    expect(catchBlock).toContain('reload();');
    expect(catchBlock).toContain('stepsFromFailure(err.body)');
  });

  it('uses no blocking browser dialog', () => {
    expect(tabSrc).not.toMatch(/window\.confirm|[^.]confirm\(/);
  });

  it('hands the verified state to the page after a success, and nothing after a failure', () => {
    const run = tabSrc.slice(tabSrc.indexOf('const run = async'), tabSrc.indexOf('} finally {'));
    expect(run.slice(0, run.indexOf('} catch (err) {'))).toContain('onChanged(result.state);');
    expect(run.slice(run.indexOf('} catch (err) {'))).toContain('onChanged();');
  });

  it('names the runtime only for an agent that has no registration', () => {
    expect(tabSrc).toContain('const runtimeArn = hasRegistration(agent) ? null : agent.agent_arn ?? null;');
  });

  it('sends the contain again to stop the remaining sessions, with the same confirmation and reason', () => {
    expect(tabSrc).toContain("const action = confirming === 'release' ? 'release' : 'contain';");
    expect(tabSrc).toContain('repeatEffects(sweepCounts(view).scheduled > 0 || retrySweeps)');
    expect(tabSrc).toContain('`Stop the remaining sessions of ${named}?`');
  });

  it('reads the state again only while a sweep is pending, and never fails the page on such a read', () => {
    const poll = tabSrc.slice(tabSrc.indexOf('const watching = '), tabSrc.indexOf('const [confirming, setConfirming]'));
    // Watching ends with the last sweep, with a release, and after a bounded number of reads.
    expect(poll).toContain('const watching = sweepsPending(view) && polls < SWEEP_POLL_LIMIT;');
    expect(poll).toContain('if (!watching || !loaded) return;');
    // The page says that it reads again only while it does.
    expect(tabSrc).toContain('{watching ? ` This is read again every ${SWEEP_POLL_SECONDS} seconds.` : \'\'}');
    expect(poll).toContain('SWEEP_POLL_SECONDS * 1000');
    expect(poll).toContain('window.clearTimeout(timer);');
    // A hidden page asks nothing, and a failed read only schedules the next one.
    expect(poll).toContain('if (document.hidden) {');
    expect(poll).not.toMatch(/setFailure|reload\(\)/);
    // Only GET: the poll uses the read of the containment view.
    expect(poll).toContain('containmentApi.get(agent.id)');
    expect(poll).not.toMatch(/containmentApi\.(contain|release)/);
  });

  it('shows each sweep with its time and counts to the roles that are sent the events, and makes sweep rows quieter', () => {
    expect(tabSrc).toContain('const sweeps = incident ? sweepLines(view) : [];');
    expect(tabSrc).toContain('<ul aria-label="Background sweeps so far"');
    // A sweep is not a decision: smaller, muted, and its outcome in words instead of a chip.
    expect(tabSrc).toContain("const quiet = row.action === 'sweep';");
    expect(tabSrc).toContain("const tone = quiet ? 'text-xs text-slate-600' : 'text-slate-700';");
    expect(tabSrc).toContain('{quiet ? sweepOutcomeLabel(row.outcome) : <Badge cls={`${outcome.cls} whitespace-nowrap`} label={outcome.label} />}');
  });

  it('shows the remedy as a disabled button with the reason beside it only after the API said that a contain came too soon', () => {
    expect(tabSrc).toContain('const repeatWait = tooSoon > 0 && offerRepeat ? retryNote(tooSoon) : null;');
    // The button never depends on how many sweeps have reported.
    expect(tabSrc).not.toMatch(/repeatBlocked|REPEAT_PENDING_NOTE/);
    // The clock that tells when unreported sweeps are given up is read at each re-read, not in the render.
    expect(tabSrc).toContain('const offered = offeredContainment(view, who, clock);');
    expect(tabSrc).toContain('const [clock, setClock] = useState(() => Date.now());');
    const blocked = tabSrc.slice(tabSrc.indexOf("{repeatWait && confirming !== 'repeat' && ("));
    expect(blocked.slice(0, 400)).toContain('disabled aria-describedby="repeat-unavailable"');
    expect(blocked.slice(0, 600)).toContain('<p id="repeat-unavailable" className="text-sm text-slate-800">{repeatWait}</p>');
    // What the API said about when a contain does its work again is kept only for that long.
    expect(tabSrc).toContain("setTooSoon(action === 'contain' ? retryAfterSeconds(result) : 0);");
    expect(tabSrc).toContain('const timer = window.setTimeout(() => setTooSoon(0), tooSoon * 1000);');
  });

  it('labels the result of the contain sent again from what was confirmed', () => {
    expect(tabSrc).toContain("const repeat = confirming === 'repeat';");
    expect(tabSrc).toContain('setLast({ action, repeat, result });');
    expect(tabSrc).toContain('resultHeadline(last.action, last.result, last.repeat)');
  });

  it('shows a role that is not sent the incident record since when the agent is contained, and no history table', () => {
    expect(tabSrc).toContain('const incident = showsIncidentRecord(view, who);');
    expect(tabSrc).toContain("{state === 'contained' && !incident && view.contained_at && (");
    expect(tabSrc).toContain('Contained since {formatDate(view.contained_at)}.');
    const history = tabSrc.slice(tabSrc.indexOf('id="containment-history"'));
    expect(history.indexOf('{!incident ? (')).toBeGreaterThan(-1);
    expect(history.indexOf('{!incident ? (')).toBeLessThan(history.indexOf('rows.length === 0'));
    // One muted line, not a card that could read as an empty history.
    expect(history).toContain('<p className="text-sm text-slate-600">{INCIDENT_RECORD_NOTE}</p>');
  });

  it('shows the quiet time, the partial warning and the sweeps to every role', () => {
    const card = tabSrc.slice(tabSrc.indexOf('aria-labelledby="containment-state" className={`rounded-xl border p-5 ${stateView.cls}`}'));
    expect(card).toContain('{sessions.quiet && ');
    expect(card).toContain('{sessions.partial && ');
    expect(card).toContain('{sessions.sweeps && (');
    expect(card).toContain('{sessions.unconfirmed && ');
  });

  it('shows the API’s note on a known state, and does not then guess that the agent was contained by other means', () => {
    expect(tabSrc).toContain('{stateView.note && <p className="mt-2 text-sm font-medium text-amber-900">{stateView.note}</p>}');
    expect(tabSrc).toContain("{state === 'contained' && !view.contained_by_label && !view.contained_at && !stateView.note && (");
  });

  it('says so when the history lists only its newest entries, to a role that is shown the history', () => {
    expect(tabSrc).toContain('{incident && view.events_truncated === true && <p className="text-xs text-slate-600 mt-2">{HISTORY_TRUNCATED_NOTE}</p>}');
    expect(HISTORY_TRUNCATED_NOTE).toBe('Only the newest entries are listed. Older entries exist and are not shown here.');
  });

  it('shows its own session sentence only when the API’s session step has none', () => {
    expect(tabSrc).toContain("lastSteps.some((step) => step.id === 'sessions' && !!step.detail) ? null : sessionsText(last?.result.sessions)");
  });
});
