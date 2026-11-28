// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import type { ContainmentResult, ContainmentStep, ContainmentView } from './containmentClient';
import type { AuditEvent } from './registrationsClient';

/** Pure view rules for containment: wording, and which action a caller is offered. */

export type ContainmentState = 'contained' | 'not_contained' | 'unknown';

/** Narrows the state. Only `contained` reads as contained; an unknown value is never "not contained". */
export function containmentState(view: Pick<ContainmentView, 'state'> | null | undefined): ContainmentState {
  const raw = (view?.state ?? '').trim().toLowerCase();
  if (raw === 'contained') return 'contained';
  if (raw === 'not_contained') return 'not_contained';
  return 'unknown';
}

export const STATE_VIEW: Record<ContainmentState, { heading: string; body: string; cls: string }> = {
  contained: {
    heading: 'Contained',
    body: 'Invocations of this agent are denied. Nothing was deleted, and it can be released.',
    cls: 'border-red-300 bg-red-50',
  },
  // What the portal knows, and no more: its own statement is not in the policy. It does not say
  // that the agent can be invoked. A statement with the portal's identifier in another shape,
  // or one written by other means, may deny invocation, and the API says so in `detail`.
  not_contained: { heading: 'Not contained', body: 'Invocations of this agent are not denied by the portal.', cls: 'border-slate-200 bg-white' },
  unknown: {
    heading: 'Containment state unknown',
    body: 'The runtime’s resource policy could not be read.',
    cls: 'border-slate-300 bg-slate-50',
  },
};

/** True when the API says the agent has no runtime: there is nothing to contain. */
export function hasNoRuntime(view: Pick<ContainmentView, 'runtime_arn'> | null | undefined): boolean {
  return !!view && (view.runtime_arn === null || view.runtime_arn === '');
}

export const NOT_READABLE = {
  heading: 'Not readable',
  body: 'The portal has no role in this agent’s account, so it cannot read its state or contain it.',
  cls: 'border-slate-300 bg-slate-50',
};

/**
 * The state card. An unknown state gives the API's own reason when it sent one, and never
 * reads as "not contained".
 */
export function stateCard(
  view: Pick<ContainmentView, 'state' | 'detail' | 'runtime_arn'>,
): { heading: string; body: string; cls: string; note: string | null } {
  const state = containmentState(view);
  const detail = view.detail?.trim();
  // With a known state the API's sentence is something to know about it, shown as sent: a
  // statement with the portal's identifier that is not the one the portal writes (it may or may
  // not deny invocation), or a holder that could not be established.
  if (state !== 'unknown') return { ...STATE_VIEW[state], note: detail || null };
  if (hasNoRuntime(view)) {
    return { heading: 'No runtime to contain', body: detail || 'This agent has no runtime.', cls: STATE_VIEW.unknown.cls, note: null };
  }
  return {
    heading: STATE_VIEW.unknown.heading,
    body: `${detail || STATE_VIEW.unknown.body} Whether the agent can be invoked is therefore not known.`,
    cls: STATE_VIEW.unknown.cls,
    note: null,
  };
}

// Neither change is instant, and the two directions differ. The API says how long each can
// take; these are what it measured, used only when it sends no number.
export const CONTAIN_DELAY_SECONDS = 90;
export const RELEASE_DELAY_SECONDS = 300;

/** A delay in words: "about 90 seconds", "about 5 minutes". Never "now". */
export function aboutDuration(seconds: number | null | undefined, fallback: number): string {
  const value = typeof seconds === 'number' && Number.isFinite(seconds) && seconds > 0 ? seconds : fallback;
  if (value >= 120) {
    const minutes = Math.round(value / 60);
    return `about ${minutes} minutes`;
  }
  return `about ${Math.round(value)} seconds`;
}

/** What "Contain agent" does, stated before the user confirms. */
export function containEffects(delaySeconds: number | null | undefined): string[] {
  return [
    // The deny spreads host by host: the page does not promise more than the service does.
    `New invocations of this agent are denied. An occasional call can still get through for ${aboutDuration(delaySeconds, CONTAIN_DELAY_SECONDS)}.`,
    'Sessions that are running are stopped.',
    'Nothing is deleted: the runtime, its configuration and its data stay as they are.',
    'It is reversible: a different person with the authority to release can release the agent.',
  ];
}

/** What "Release agent" does. A release takes longer to apply everywhere than a contain. */
export function releaseEffects(delaySeconds: number | null | undefined): string[] {
  return [
    `The agent can be invoked again. Some calls can still be refused for ${aboutDuration(delaySeconds, RELEASE_DELAY_SECONDS)} while the change spreads.`,
    'Sessions that were stopped are not restarted.',
  ];
}

/**
 * What "Stop remaining sessions" does. It is the contain request sent again: the API leaves the
 * policy alone, stops the sessions it finds and, where the portal has a sweep queue, schedules
 * the background sweeps again. `withSweeps` says whether this containment has sweeps at all.
 */
export function repeatEffects(withSweeps: boolean): string[] {
  const effects = [
    'The agent stays contained. Its policy is not changed.',
    'Sessions that the portal can find and that are still running are stopped.',
  ];
  if (withSweeps) effects.push('Background sweeps are scheduled again.');
  effects.push('Nothing is deleted, and who may release the agent does not change.');
  return effects;
}

/**
 * How long until a contain does its work again, in seconds, when the API answered that this one
 * came too soon after the last and therefore did nothing. Zero otherwise.
 */
export function retryAfterSeconds(result: Pick<ContainmentResult, 'retry_after_seconds'> | null | undefined): number {
  const seconds = result?.retry_after_seconds;
  return typeof seconds === 'number' && Number.isFinite(seconds) && seconds > 0 ? Math.ceil(seconds) : 0;
}

/** Said beside "Stop remaining sessions" after such an answer, until that time has passed. */
export function retryNote(seconds: number): string {
  return `Sessions can be swept again in ${aboutDuration(seconds, seconds)}.`;
}

/**
 * The API's pause between two contains that do their work, when the earlier one scheduled
 * background sweeps. The figure is the API's; the page only uses it to say what can happen.
 */
export const REPEAT_AFTER_SECONDS = 900;

/**
 * Said in the confirmation of "Stop remaining sessions" when the contain can come too soon. The
 * API answers such a contain at once and does nothing, and the page does not hold the button
 * back for it, so the person is told before a reason is asked for.
 */
export const REPEAT_TOO_SOON_CAVEAT = `If the last contain was less than ${aboutDuration(REPEAT_AFTER_SECONDS, REPEAT_AFTER_SECONDS)} ago, or one of its background sweeps is still running, nothing more is done and the answer says when to ask again.`;

export const NOT_ENABLED_NOTE = 'Containment is not available for this agent. Its cell has not given the portal the authority to contain it.';
export const SAME_PERSON_NOTE = 'You contained this agent. A different person must release it.';
export const NO_CONTAIN_AUTHORITY_NOTE = 'Containing an agent needs the containment authority, which you do not hold.';
export const NO_RELEASE_AUTHORITY_NOTE = 'Releasing an agent needs the authority to release, which you do not hold.';
export const UNKNOWN_STATE_NOTE = 'No action is offered while the containment state cannot be read.';
export const OTHER_MEANS_NOTE =
  'This agent was contained by other means than the portal, so who contained it, when and why are not recorded here.';
export const PARTIAL_NOTE =
  'Not every session that was running was stopped. Invocations are denied all the same, including on a session that is still running.';
export const SWEEPS_UNCONFIRMED_NOTE = 'Every background sweep has run, and none confirmed that no session is still running.';
export const INCIDENT_RECORD_NOTE = 'Who contained this agent, why, and the history are shown to the security, platform and SRE roles.';

/**
 * The background sweeps of the containment that holds, as two whole numbers. `done` is never
 * more than `scheduled`, and a missing or malformed count is zero.
 */
export function sweepCounts(view: Pick<ContainmentView, 'sweeps'> | null | undefined): { scheduled: number; done: number } {
  const whole = (n: unknown) => (typeof n === 'number' && Number.isFinite(n) && n > 0 ? Math.floor(n) : 0);
  const scheduled = whole(view?.sweeps?.scheduled);
  return { scheduled, done: Math.min(whole(view?.sweeps?.done), scheduled) };
}

/** True while a background sweep of a contained agent has not run yet: the state is worth reading again. */
export function sweepsPending(view: Pick<ContainmentView, 'state' | 'sweeps'> | null | undefined): boolean {
  if (containmentState(view) !== 'contained') return false;
  const { scheduled, done } = sweepCounts(view);
  return done < scheduled;
}

/** How often the state is read again while a sweep is pending, and for how many reads at most. */
export const SWEEP_POLL_SECONDS = 20;
export const SWEEP_POLL_LIMIT = 120;

export interface SessionsStatus {
  /**
   * Set once a complete sweep has run and nothing later takes its certainty away. It is the later
   * and stronger statement, so it replaces the partial warning.
   */
  quiet: string | null;
  /**
   * Said in its place when a later sweep failed or never reported: what that complete sweep
   * found at the time, and no more. The API keeps `quiet_at` for the whole containment.
   */
  quietOnce: string | null;
  /** What came after that complete sweep: the newest sweep failed, or one never reported. Null otherwise. */
  later: 'failed' | 'overdue' | null;
  /** The contain request did not stop every session it found, and no sweep has since confirmed that none is running. */
  partial: boolean;
  /** For example "Background sweeps: 1 of 2 done." Null when none was scheduled. */
  sweeps: string | null;
  /** Every scheduled sweep has run and none confirmed that no session is running. */
  unconfirmed: boolean;
  /** A sweep never reported and none confirmed that no session is running. Only a role that is sent the events can tell. */
  overdue: boolean;
}

/**
 * What is known about the running sessions of a contained agent. Every role is shown this: it
 * is part of the state, not of the incident record. An agent that is not contained has nothing
 * to say here.
 */
export function sessionsStatus(view: SessionFacts | null | undefined, formatTime: (iso: string) => string, nowMs = 0): SessionsStatus {
  if (!view || containmentState(view) !== 'contained') {
    return { quiet: null, quietOnce: null, later: null, partial: false, sweeps: null, unconfirmed: false, overdue: false };
  }
  const { scheduled, done } = sweepCounts(view);
  const quietAt = (view.quiet_at ?? '').trim();
  // Said only on the evidence of the contain's own event: without it the page counts from when
  // the containment began, and a later contain's sweeps could still be due.
  const overdue = !!lastWorkingContain(view) && sweepsOverdue(view, nowMs);
  // `quiet_at` is the first time the agent was known to be quiet and stays set. A sweep that
  // failed after it, or one that never reported, was there to catch a session that started
  // late: "no running session since" would then say more than is known. Only a role that is
  // sent the events can tell.
  const later = !quietAt ? null : lastSweepFailed(view) ? 'failed' : overdue ? 'overdue' : null;
  return {
    quiet:
      quietAt && !later
        ? `No running session since ${formatTime(quietAt)}. Every session the portal could find has ended or was stopped.`
        : null,
    quietOnce: quietAt && later ? `A background sweep at ${formatTime(quietAt)} left no session running.` : null,
    later,
    partial: !quietAt && view.partial === true,
    sweeps: scheduled > 0 ? `Background sweeps: ${done} of ${scheduled} done.` : null,
    unconfirmed: !quietAt && scheduled > 0 && done >= scheduled,
    overdue: !quietAt && overdue,
  };
}

/** The background sweeps of the containment that holds, newest first: the sweep events since it began. */
function sweepsSince(view: Pick<ContainmentView, 'contained_at' | 'events'>): AuditEvent[] {
  const began = (view.contained_at ?? '').trim();
  // A containment made by other means has no sweeps of the portal's.
  if (!began) return [];
  return (view.events ?? []).filter((event) => event.action === 'sweep' && event.at >= began);
}

/**
 * True when the newest background sweep of this containment did not complete. Only a role that
 * is sent the events can tell.
 */
export function lastSweepFailed(view: Pick<ContainmentView, 'contained_at' | 'events'> | null | undefined): boolean {
  return !!view && sweepsSince(view)[0]?.outcome === 'failed';
}

type SessionFacts = Pick<ContainmentView, 'state' | 'partial' | 'sweeps' | 'quiet_at'> & Partial<Pick<ContainmentView, 'contained_at' | 'events'>>;

/**
 * How long after its contain a sweep that has not reported is given up. The API then lets a
 * contain do its work again; the figure is the API's (the last sweep starts 15 minutes after
 * the contain and runs for 15 at most).
 */
export const SWEEPS_GIVEN_UP_SECONDS = 1800;

/**
 * The newest contain of this containment that did its work, when the events hold it. Such a
 * contain's result carries session counts; one that was answered at once because it came too
 * soon does not. A role that is not sent the events has none.
 */
function lastWorkingContain(view: Partial<Pick<ContainmentView, 'contained_at' | 'events'>>): AuditEvent | undefined {
  const began = (view.contained_at ?? '').trim();
  return (view.events ?? []).find(
    (event) =>
      event.action === 'contain' &&
      event.phase === 'result' &&
      (event.outcome === 'allowed' || event.outcome === 'unchanged') &&
      typeof event.sessions_found === 'number' &&
      (!began || event.at >= began),
  );
}

/** When that contain was made. Without its event it is when the containment began. */
function lastWorkingContainAt(view: Partial<Pick<ContainmentView, 'contained_at' | 'events'>>): string {
  return lastWorkingContain(view)?.at ?? (view.contained_at ?? '').trim();
}

/** Said in the state card when a sweep never reported: why the remedy is offered for a containment that was not partial. */
export const SWEEPS_OVERDUE_NOTE = `A background sweep has still not reported ${SWEEPS_GIVEN_UP_SECONDS / 60} minutes after its contain, and none confirmed that no session is still running.`;

/** The same two facts when an earlier sweep did leave no session running: what came later, and what it can mean. */
export const SWEEP_FAILED_LATER_NOTE = 'The newest background sweep did not complete. A session that started later may still be running.';
export const SWEEPS_OVERDUE_LATER_NOTE = `A later background sweep has still not reported ${SWEEPS_GIVEN_UP_SECONDS / 60} minutes after its contain. A session that started later may still be running.`;

/**
 * True when a sweep of this containment has not reported long after it was due: it was lost,
 * or its run was cut short, and it never will. The counts then stay "1 of 2 done" for good.
 * `nowMs` is the clock; without one (zero) nothing is called overdue.
 */
export function sweepsOverdue(view: (Pick<ContainmentView, 'state' | 'sweeps'> & Partial<Pick<ContainmentView, 'contained_at' | 'events'>>) | null | undefined, nowMs: number): boolean {
  if (!view || !nowMs || !sweepsPending(view)) return false;
  const at = Date.parse(lastWorkingContainAt(view));
  return Number.isFinite(at) && nowMs - at >= SWEEPS_GIVEN_UP_SECONDS * 1000;
}

/**
 * True when a contain sent again now can come too soon for the API, which then answers at once
 * and does nothing: a sweep of this containment can still be running, or the newest contain
 * that did its work is less than the API's pause old. Only a containment with sweeps has that
 * pause. When the page cannot tell (no clock, no time) it says that it can happen.
 */
export function repeatMayComeTooSoon(
  view: (Pick<ContainmentView, 'state' | 'sweeps'> & Partial<Pick<ContainmentView, 'contained_at' | 'events'>>) | null | undefined,
  nowMs: number,
): boolean {
  if (!view || containmentState(view) !== 'contained' || sweepCounts(view).scheduled === 0) return false;
  if (sweepsPending(view) && !sweepsOverdue(view, nowMs)) return true;
  const at = Date.parse(lastWorkingContainAt(view));
  return !nowMs || !Number.isFinite(at) || nowMs - at < REPEAT_AFTER_SECONDS * 1000;
}

/**
 * True when sessions of a contained agent may still be running. The API's remedy is to contain
 * the agent again, which leaves the policy alone and sweeps the sessions once more.
 *
 * Two reasons hold whatever `quiet_at` says: the newest sweep failed, or a sweep never
 * reported. `quiet_at` is set by the first complete sweep and stays set; the sweep after it is
 * there for a session that started late, so its failure or its silence is news. The other two
 * reasons (the contain request was partial, every sweep ran) are settled once a sweep has
 * confirmed quiet.
 */
export function sessionsMayRemain(view: SessionFacts | null | undefined, nowMs = 0): boolean {
  if (!view || containmentState(view) !== 'contained') return false;
  if (lastSweepFailed(view) || sweepsOverdue(view, nowMs)) return true;
  if ((view.quiet_at ?? '').trim()) return false;
  const { scheduled, done } = sweepCounts(view);
  return view.partial === true || (scheduled > 0 && done >= scheduled);
}

export interface SweepLine {
  key: string;
  /** "Sweep 2", or "Sweep" when the event carries no number. */
  label: string;
  at: string;
  /** For example "3 checked, 2 stopped, 0 already ended, 1 failed". Empty when the sweep ended before it listed any session. */
  counts: string;
  /** "Complete", "Incomplete" or "Skipped". */
  outcome: string;
}

const SWEEP_OUTCOME: Record<string, string> = { allowed: 'Complete', failed: 'Incomplete', skipped: 'Skipped' };

/**
 * A sweep's outcome in words. A sweep is the portal's own act, not a decision: it is not
 * "allowed" or "denied". It is complete when it read every source to its end and left no
 * session unstopped. An unknown outcome is shown as recorded.
 */
export function sweepOutcomeLabel(outcome: string): string {
  return Object.prototype.hasOwnProperty.call(SWEEP_OUTCOME, outcome) ? SWEEP_OUTCOME[outcome] : outcome || 'Unknown';
}

/**
 * Each background sweep of the containment that holds, oldest first, with its time and counts.
 * A sweep has to try every session of the last eight hours, ended or not, so its first count is
 * what it checked, not what was running.
 */
export function sweepLines(view: Pick<ContainmentView, 'state' | 'contained_at' | 'events'> | null | undefined): SweepLine[] {
  if (!view || containmentState(view) !== 'contained') return [];
  const number = (n: number | null | undefined) => (typeof n === 'number' && Number.isFinite(n) ? n : 0);
  return sweepsSince(view)
    .slice()
    .reverse()
    .map((event) => ({
      key: event.event_id,
      label: typeof event.sweep === 'number' ? `Sweep ${event.sweep}` : 'Sweep',
      at: event.at,
      counts:
        typeof event.sessions_found === 'number'
          ? `${event.sessions_found} checked, ${number(event.sessions_stopped)} stopped, ${number(event.sessions_not_active)} already ended, ${number(event.sessions_failed)} failed`
          : '',
      outcome: sweepOutcomeLabel(event.outcome),
    }));
}

/**
 * True when the incident record (who, why, the history) is shown. The API sends it only to a
 * caller whose role can contain or release; whatever it did send is shown.
 */
export function showsIncidentRecord(
  view: Pick<ContainmentView, 'contained_by_label' | 'reason' | 'events'> | null | undefined,
  who: { canContain: boolean; canRelease: boolean },
): boolean {
  return who.canContain || who.canRelease || (view?.events?.length ?? 0) > 0 || !!view?.contained_by_label || !!view?.reason;
}

export interface OfferedContainment {
  contain: boolean;
  release: boolean;
  /**
   * "Stop remaining sessions": the contain request sent again for an agent that is contained
   * while some of its sessions may still be running.
   */
  repeat: boolean;
  /**
   * True for the person who contained the agent: Release is shown, visibly unavailable, with the
   * reason next to it, instead of being hidden or failing on click.
   */
  releaseBlocked: boolean;
  /** Why an action is not offered. */
  note: string | null;
}

/**
 * Which action to offer. This only decides what is shown: the server enforces the authority,
 * the tenant and the two-person rule itself, and its refusal is displayed if a request is made
 * anyway.
 */
export function offeredContainment(
  view:
    | (Pick<ContainmentView, 'state' | 'contained_by_me' | 'enabled' | 'runtime_arn' | 'partial' | 'sweeps' | 'quiet_at'> &
        Partial<Pick<ContainmentView, 'contained_at' | 'events'>>)
    | null
    | undefined,
  who: { canContain: boolean; canRelease: boolean },
  nowMs = 0,
): OfferedContainment {
  const none = { contain: false, release: false, repeat: false, releaseBlocked: false };
  const state = containmentState(view);
  // The state card already says that there is no runtime.
  if (hasNoRuntime(view)) return { ...none, note: null };
  // A state that cannot be read comes first: that is why nothing is offered, and the state card
  // gives the API's reason. The API also sends `enabled: false` for some of those states (a
  // registration that spells its runtime's ARN another way), where "the cell has not given the
  // portal the authority" would not be the reason.
  if (state === 'unknown') return { ...none, note: who.canContain || who.canRelease ? UNKNOWN_STATE_NOTE : null };
  if (view?.enabled === false) return { ...none, note: NOT_ENABLED_NOTE };
  if (state === 'not_contained') {
    return who.canContain ? { ...none, contain: true, note: null } : { ...none, note: NO_CONTAIN_AUTHORITY_NOTE };
  }
  if (state === 'contained') {
    // Containing again is open to whoever may contain, including the person who contained it:
    // it does not change who holds the containment. It does not wait for the sweeps to report:
    // one that was lost never does. A contain that comes too soon is answered at once by the
    // API, which says when it does its work again.
    const repeat = who.canContain && sessionsMayRemain(view, nowMs);
    if (!who.canRelease) return { ...none, repeat, note: NO_RELEASE_AUTHORITY_NOTE };
    // The two-person rule: the person who contained an agent cannot release it.
    if (view?.contained_by_me === true) return { ...none, repeat, releaseBlocked: true, note: SAME_PERSON_NOTE };
    return { ...none, repeat, release: true, note: null };
  }
  return { ...none, note: null };
}

const STEP_STATUS: Record<string, { label: string; cls: string; ok: boolean }> = {
  done: { label: 'Done', cls: 'bg-emerald-50 text-emerald-800', ok: true },
  unchanged: { label: 'No change needed', cls: 'bg-slate-100 text-slate-700', ok: true },
  skipped: { label: 'Skipped', cls: 'bg-slate-100 text-slate-700', ok: true },
  // The background sweeps a contain leaves on the queue: they run after the request.
  scheduled: { label: 'Scheduled', cls: 'bg-blue-50 text-blue-800', ok: true },
  partial: { label: 'Partly done', cls: 'bg-amber-50 text-amber-900', ok: false },
  failed: { label: 'Failed', cls: 'bg-red-50 text-red-800', ok: false },
};

/** A step's status in words. An unrecognised status is shown as recorded and counts as not done. */
export function stepStatusView(status: string | null | undefined): { label: string; cls: string; ok: boolean } {
  const key = (status ?? '').trim().toLowerCase();
  return Object.prototype.hasOwnProperty.call(STEP_STATUS, key)
    ? STEP_STATUS[key]
    : { label: status?.trim() || 'Unknown', cls: 'bg-slate-100 text-slate-700', ok: false };
}

/**
 * True when part of the action did not complete: the API says so, a step is not done, or a
 * session could not be stopped. A partial result is always shown as partial, never as success.
 */
export function isPartial(result: Pick<ContainmentResult, 'partial' | 'steps' | 'sessions'> | null | undefined): boolean {
  if (!result) return false;
  if (result.partial === true) return true;
  if ((result.steps ?? []).some((step) => !stepStatusView(step.status).ok)) return true;
  const sessions = result.sessions;
  return !!sessions && (sessions.discovery !== 'ok' || (sessions.failed ?? 0) > 0 || (sessions.not_attempted ?? 0) > 0);
}

/**
 * True when a contain could not leave its background sweeps on the queue. The view does not say
 * so afterwards (it looks like a containment without sweeps), so the result is asked. The API's
 * remedy is to contain again.
 */
export function sweepsNotScheduled(result: Pick<ContainmentResult, 'steps'> | null | undefined): boolean {
  return (result?.steps ?? []).some((step) => step.id === 'background' && !stepStatusView(step.status).ok);
}

/**
 * What did not complete, as a clause, or an empty string when everything did. The API calls a
 * contain partial for two reasons: its session step was not clean, or the background sweeps
 * could not be scheduled.
 */
export function incompleteWords(result: Pick<ContainmentResult, 'partial' | 'steps' | 'sessions'> | null | undefined): string {
  if (!result || !isPartial(result)) return '';
  const notOk = (id: string) => (result.steps ?? []).some((step) => step.id === id && !stepStatusView(step.status).ok);
  const sessions = result.sessions;
  const sessionsLeft =
    notOk('sessions') || (!!sessions && (sessions.discovery !== 'ok' || (sessions.failed ?? 0) > 0 || (sessions.not_attempted ?? 0) > 0));
  const sweepsLeft = sweepsNotScheduled(result);
  const parts: string[] = [];
  if (sessionsLeft || (result.partial === true && !sweepsLeft)) parts.push('not every running session was stopped');
  if (sweepsLeft) parts.push('the background sweeps could not all be scheduled');
  return parts.length > 0 ? parts.join(' and ') : 'a step did not complete';
}

const capitalised = (text: string) => text.charAt(0).toUpperCase() + text.slice(1);
const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;
const sentence = (text: string) => (/[.!?]$/.test(text) ? text : `${text}.`);

/**
 * Where the sessions were found, for example " (3 in logs)" or " (2 in traces, 3 in logs)".
 * Only the sources the API names are given: traces are a source a cell opts in to, and one that
 * was not asked is not shown as zero. Empty when no source is named.
 */
function sourcesText(sources: NonNullable<ContainmentResult['sessions']>['sources']): string {
  const parts: string[] = [];
  if (typeof sources?.spans === 'number') parts.push(`${sources.spans} in traces`);
  if (typeof sources?.log_streams === 'number') parts.push(`${sources.log_streams} in logs`);
  return parts.length > 0 ? ` (${parts.join(', ')})` : '';
}

/**
 * What happened to the running sessions, in one or two sentences, or null when the answer
 * carries no session result. The API's step list says the same in its own words; this is what
 * the page falls back to when a step has no sentence.
 *
 * `discovery` is `ok`, `ok; <what was incomplete>`, or a reason why nothing was listed or
 * stopped. Only the first is clean.
 */
export function sessionsText(sessions: ContainmentResult['sessions']): string | null {
  if (!sessions) return null;
  const discovery = (sessions.discovery ?? '').trim();
  if (!/^ok\b/i.test(discovery)) {
    return sentence(`Running sessions were not stopped: ${discovery || 'no reason was given'}`);
  }
  const found = sessions.found ?? 0;
  let text = 'No recent session was found to stop.';
  if (found > 0) {
    const errors = (sessions.stop_errors ?? []).filter(Boolean);
    const parts = [`${plural(found, 'session', 'sessions')} found${sourcesText(sessions.sources)}`, `${sessions.stopped ?? 0} stopped`];
    if ((sessions.not_active ?? 0) > 0) parts.push(`${sessions.not_active} already ended`);
    if ((sessions.failed ?? 0) > 0) parts.push(`${sessions.failed} could not be stopped${errors.length > 0 ? ` (${errors.join(', ')})` : ''}`);
    if ((sessions.not_attempted ?? 0) > 0) parts.push(`${sessions.not_attempted} not tried before the time limit`);
    text = `${parts.join(', ')}.`;
  }
  const incomplete = discovery.replace(/^ok\s*;?\s*/i, '');
  return incomplete ? `${text} ${sentence(`Session discovery was incomplete: ${incomplete}`)}` : text;
}

/**
 * The headline for a finished action. It claims containment only when the verified state says so.
 * `repeat` is true for "Stop remaining sessions": the contain sent again for an agent that is
 * already contained. Its result is not "Contained": the policy was left alone and the sessions
 * were swept again.
 */
export function resultHeadline(action: string, result: ContainmentResult, repeat = false): string {
  const contain = action === 'contain';
  const reached = contain ? result.state === 'contained' : result.state === 'not_contained';
  // The result carries the delay of the action it reports.
  const delay = `within ${aboutDuration(result.enforcement_delay_seconds, CONTAIN_DELAY_SECONDS)}`;
  if (!reached) {
    return contain ? 'The agent could not be confirmed as contained.' : 'The agent could not be confirmed as released.';
  }
  const incomplete = contain ? incompleteWords(result) : '';
  if (result.outcome === 'unchanged') {
    // The portal's statement was not there to remove. Another statement may still deny
    // invocation; the API's step says so when it found one, and the headline claims no more.
    if (!contain) return 'This agent was not contained by the portal. Nothing was changed.';
    // Contained a moment ago: the API answered at once and did nothing. The step says when it will.
    if (retryAfterSeconds(result) > 0) return 'The agent was already contained. Nothing more was done.';
    // The sessions were swept again when the answer carries a session result.
    if (repeat && result.sessions) return incomplete ? `Sessions swept again. ${capitalised(incomplete)}.` : 'Sessions swept again.';
    // A repeated contain leaves the policy alone but still stops the sessions it finds.
    return incomplete
      ? `The agent was already contained, and its policy was not changed. ${capitalised(incomplete)}.`
      : 'The agent was already contained. Its policy was not changed.';
  }
  if (contain) {
    return incomplete ? `Contained, but ${incomplete}. Invocations are blocked ${delay}.` : `Contained. Invocations are blocked ${delay}.`;
  }
  return `Released. Some calls can still be refused for ${aboutDuration(result.enforcement_delay_seconds, RELEASE_DELAY_SECONDS)}.`;
}

/** Steps carried by a failed request (a 502 says what was and was not done). Never throws. */
export function stepsFromFailure(body: unknown): ContainmentStep[] {
  if (typeof body !== 'object' || body === null) return [];
  const steps = (body as { steps?: unknown }).steps;
  if (!Array.isArray(steps)) return [];
  return steps
    .filter((s): s is Record<string, unknown> => typeof s === 'object' && s !== null)
    .map((s, i) => ({
      id: typeof s.id === 'string' ? s.id : `step-${i}`,
      label: typeof s.label === 'string' ? s.label : typeof s.id === 'string' ? s.id : 'Step',
      status: typeof s.status === 'string' ? s.status : '',
      detail: typeof s.detail === 'string' ? s.detail : null,
    }));
}

/**
 * A recorded reason in two parts. The API writes the caller's reason followed by what was done
 * in square brackets; the page shows the reason first and what was done under it.
 */
export function splitReason(text: string | null | undefined): { reason: string; done: string } {
  const full = (text ?? '').trim();
  const at = full.indexOf(' [');
  if (at === -1 || !full.endsWith(']')) return { reason: full, done: '' };
  return { reason: full.slice(0, at).trim(), done: full.slice(at + 2, -1).trim() };
}

// A sweep is the portal's own act after a contain; its row says which sweep it was in its reason.
const EVENT_ACTION: Record<string, string> = { contain: 'Contain', release: 'Release', sweep: 'Background sweep' };

export function eventActionLabel(action: string): string {
  return Object.prototype.hasOwnProperty.call(EVENT_ACTION, action) ? EVENT_ACTION[action] : action;
}
