// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { useEffect, useRef, useState } from 'react';
import type { Agent } from '../api/client';
import { ApiRequestError, isNotFound } from '../api/client';
import { agentContext, hasRegistration, readerState } from '../components/governance/inventory';
import { resolveTenantName } from '../components/governance/tenantUi';
import { Badge, CARD, ErrorCard, Loading, TABLE_HEAD, TD, TH, formatDate } from '../components/shared/ui';
import { useAsync } from '../components/shared/useAsync';
import { useUser } from '../contexts/UserContext';
import ActionFailurePanel from './ActionFailurePanel';
import { containmentApi, type ContainmentResult, type ContainmentStep, type ContainmentView } from './containmentClient';
import {
  INCIDENT_RECORD_NOTE,
  NOT_READABLE,
  OTHER_MEANS_NOTE,
  PARTIAL_NOTE,
  REPEAT_TOO_SOON_CAVEAT,
  SAME_PERSON_NOTE,
  SWEEPS_OVERDUE_NOTE,
  SWEEPS_UNCONFIRMED_NOTE,
  SWEEP_POLL_LIMIT,
  SWEEP_POLL_SECONDS,
  containEffects,
  containmentState,
  eventActionLabel,
  isPartial,
  offeredContainment,
  releaseEffects,
  repeatEffects,
  repeatMayComeTooSoon,
  resultHeadline,
  retryAfterSeconds,
  retryNote,
  sessionsStatus,
  sessionsText,
  showsIncidentRecord,
  splitReason,
  stateCard,
  stepStatusView,
  stepsFromFailure,
  sweepCounts,
  sweepLines,
  sweepOutcomeLabel,
  sweepsNotScheduled,
  sweepsPending,
} from './containmentView';
import { classifyFailure, type ActionFailure } from './registrationsClient';
import { AUDIT_INCOMPLETE_NOTE, HISTORY_TRUNCATED_NOTE, historyRows, outcomeView } from './registrationView';

const DANGER = 'px-3.5 py-1.5 rounded-lg bg-red-700 text-white text-sm font-medium hover:bg-red-800 disabled:opacity-50';
const PRIMARY = 'px-3.5 py-1.5 rounded-lg bg-blue-700 text-white text-sm font-medium hover:bg-blue-800 disabled:opacity-50';
const SECONDARY = 'px-3.5 py-1.5 rounded-lg bg-white border border-slate-300 text-slate-700 text-sm font-medium hover:bg-slate-50 disabled:opacity-50';

/** What an action did, step by step, in the server's words. A step that did not complete says so. */
function StepList({ steps }: { steps: ContainmentStep[] }) {
  if (steps.length === 0) return null;
  return (
    <ul className="mt-2 space-y-1.5">
      {steps.map((step) => {
        const status = stepStatusView(step.status);
        return (
          <li key={step.id} className="flex flex-wrap items-baseline gap-2 text-sm">
            <Badge cls={`${status.cls} whitespace-nowrap`} label={status.label} />
            <span className="text-slate-900">{step.label}</span>
            {step.detail && <span className="text-slate-700 break-words">{step.detail}</span>}
          </li>
        );
      })}
    </ul>
  );
}

/** A recorded reason: what the person wrote, then what was done, smaller, on its own line. */
function Reason({ text }: { text: string | null | undefined }) {
  const { reason, done } = splitReason(text);
  if (!reason && !done) return <span className="text-slate-600">Not recorded</span>;
  return (
    <>
      {reason && <span className="block break-words">{reason}</span>}
      {done && <span className="block text-xs text-slate-600 break-words mt-0.5">{done}</span>}
    </>
  );
}

/**
 * What the confirmation asks. `repeat` is the contain request sent again for an agent that is
 * already contained, to stop the sessions that are left.
 */
type Confirming = 'contain' | 'release' | 'repeat';

const CONFIRM: Record<Confirming, { question: (named: string) => string; button: string; cls: string }> = {
  contain: { question: (named) => `Contain ${named}?`, button: 'Contain agent', cls: DANGER },
  release: { question: (named) => `Release ${named}?`, button: 'Release agent', cls: PRIMARY },
  repeat: { question: (named) => `Stop the remaining sessions of ${named}?`, button: 'Stop remaining sessions', cls: DANGER },
};

/**
 * Containment of one agent: its current state, who contained it and why, the actions the caller
 * may take, and the history. Part of the governed actions feature.
 */
export default function ContainmentTab({
  agent,
  onChanged,
}: {
  agent: Agent;
  /** Called after every action, with the state the action verified when it succeeded. */
  onChanged: (verifiedState?: string) => void;
}) {
  const { user } = useUser();
  const who = { canContain: user?.can_contain === true, canRelease: user?.can_release === true };
  // An agent with no registration is identified to the server by its runtime.
  const runtimeArn = hasRegistration(agent) ? null : agent.agent_arn ?? null;
  // Without a reader role in the agent's account the state cannot be read and the agent cannot
  // be contained, so nothing is asked of the API.
  const noReader = readerState(agent) === 'none';
  const { data: loaded, loading, error, cause, reload } = useAsync(
    () => (noReader ? Promise.resolve(null) : containmentApi.get(agent.id)),
    [agent.id, noReader],
    'Failed to read the containment state.',
    { keepPreviousOnReload: true },
  );
  // The background sweeps of a containment run after the request, for up to 15 minutes. While one
  // is pending the state is read again quietly: a newer read replaces the one it was made after,
  // and a read that fails changes nothing on screen and is tried again.
  // The clock, read when the tab opens and at every such read: a sweep that has not reported
  // half an hour after its contain is given up, and only a clock can tell.
  const [clock, setClock] = useState(() => Date.now());
  const [polled, setPolled] = useState<{ after: ContainmentView; view: ContainmentView } | null>(null);
  const view = polled && polled.after === loaded ? polled.view : loaded;
  // How many such reads were made since the last action on this page, and a counter that arms
  // the timer again after a read that was skipped or failed.
  const [polls, setPolls] = useState(0);
  const [rearm, setRearm] = useState(0);
  const notify = useRef(onChanged);
  useEffect(() => {
    notify.current = onChanged;
  });
  const watching = sweepsPending(view) && polls < SWEEP_POLL_LIMIT;
  const shownState = containmentState(view);
  useEffect(() => {
    if (!watching || !loaded) return;
    let cancelled = false;
    const timer = window.setTimeout(() => {
      // A page that is not looked at asks nothing; it reads again once it is.
      if (document.hidden) {
        setRearm((n) => n + 1);
        return;
      }
      containmentApi.get(agent.id).then(
        (next) => {
          if (cancelled) return;
          setPolls((n) => n + 1);
          setClock(Date.now());
          setPolled({ after: loaded, view: next });
          // Somebody else released the agent meanwhile: the page's badge follows what was read.
          if (containmentState(next) !== shownState) notify.current(next.state);
        },
        () => {
          if (cancelled) return;
          setPolls((n) => n + 1);
          setClock(Date.now());
          setRearm((n) => n + 1);
        },
      );
    }, SWEEP_POLL_SECONDS * 1000);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [watching, loaded, view, shownState, rearm, agent.id]);
  const [confirming, setConfirming] = useState<Confirming | null>(null);
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<ActionFailure | null>(null);
  // `repeat`: the contain sent again to sweep the sessions of an agent that is already contained.
  const [last, setLast] = useState<{ action: 'contain' | 'release'; repeat: boolean; result: ContainmentResult } | null>(null);
  const [failedSteps, setFailedSteps] = useState<ContainmentStep[]>([]);
  // The API answered that a contain came too soon after the last and did nothing: for how many
  // seconds, from that answer. "Stop remaining sessions" is unavailable until they have passed.
  const [tooSoon, setTooSoon] = useState(0);
  useEffect(() => {
    if (tooSoon <= 0) return;
    const timer = window.setTimeout(() => setTooSoon(0), tooSoon * 1000);
    return () => window.clearTimeout(timer);
  }, [tooSoon]);

  const refresh = () => {
    setFailure(null);
    reload();
  };

  const open = (action: Confirming) => {
    setConfirming(action);
    setReason('');
    setFailure(null);
    // What the confirmation says can depend on how long ago the last contain was.
    setClock(Date.now());
  };

  const run = async () => {
    const trimmed = reason.trim();
    // The button is enabled only once a reason is entered; nothing is sent without one.
    if (!confirming || !trimmed) return;
    // Stopping the remaining sessions is the contain request again: the API leaves the policy alone.
    const action = confirming === 'release' ? 'release' : 'contain';
    const repeat = confirming === 'repeat';
    setBusy(true);
    setFailure(null);
    setFailedSteps([]);
    try {
      const result =
        action === 'contain'
          ? await containmentApi.contain(agent.id, trimmed, runtimeArn)
          : await containmentApi.release(agent.id, trimmed, runtimeArn);
      setLast({ action, repeat, result });
      setClock(Date.now());
      setTooSoon(action === 'contain' ? retryAfterSeconds(result) : 0);
      setConfirming(null);
      // A contain schedules sweeps of its own: they are watched from the start.
      setPolls(0);
      reload();
      // The agent's badge and flags are read from the agent record, which can lag for a moment:
      // the state this action verified is handed over with it.
      onChanged(result.state);
    } catch (err) {
      setFailure(classifyFailure(err, action === 'contain' ? 'The agent could not be contained' : 'The agent could not be released'));
      // A request that failed part-way says which steps were and were not done.
      setFailedSteps(err instanceof ApiRequestError ? stepsFromFailure(err.body) : []);
      setLast(null);
      // The state is read again: a refusal is in the history, and after a failure the page
      // must show what state the agent is really in.
      reload();
      onChanged();
    } finally {
      setBusy(false);
    }
  };

  if (noReader) {
    return (
      <section aria-labelledby="containment-state" className={`rounded-xl border p-5 ${NOT_READABLE.cls}`}>
        <h2 id="containment-state" className="text-base font-semibold text-slate-900">{NOT_READABLE.heading}</h2>
        <p className="text-sm text-slate-800 mt-1">{NOT_READABLE.body}</p>
      </section>
    );
  }
  if (loading && !view) return <Loading label="Reading the containment state…" />;
  if (isNotFound(cause)) {
    return <div className={`${CARD} p-5 text-sm text-slate-700`}>No containment record exists for this agent.</div>;
  }
  if (error || !view) {
    return <ErrorCard title="Couldn’t read the containment state" message={error ?? 'No data was returned.'} onRetry={reload} />;
  }

  const state = containmentState(view);
  const stateView = stateCard(view);
  const offered = offeredContainment(view, who, clock);
  // Who contained the agent, why, and the history are sent only to a role that can contain or release.
  const incident = showsIncidentRecord(view, who);
  const sessions = sessionsStatus(view, (iso) => formatDate(iso), clock);
  // Each sweep with its time and counts, for the roles that are sent the events.
  const sweeps = incident ? sweepLines(view) : [];
  const rows = historyRows(view.events);
  const lastPartial = last ? isPartial(last.result) : false;
  // The API's steps say what happened to the sessions. The page's own sentence is used only
  // when the session step carries none.
  const lastSteps = last?.result.steps ?? [];
  const lastSessions = lastSteps.some((step) => step.id === 'sessions' && !!step.detail) ? null : sessionsText(last?.result.sessions);
  // A contain made on this page that could not schedule its sweeps. The view cannot tell this from
  // a containment that has no sweeps; the result can, and its remedy is the contain again.
  const retrySweeps =
    last?.action === 'contain' && state === 'contained' && who.canContain && view.enabled !== false && sweepsNotScheduled(last.result);
  const offerRepeat = offered.repeat || retrySweeps;
  // Why the remedy is shown but cannot be used right now, or null when it can: the API has just
  // answered that a contain came too soon, and said when one does its work again. The page does
  // not hold the button back for sweeps that have yet to report: one that was lost never does.
  const repeatWait = tooSoon > 0 && offerRepeat ? retryNote(tooSoon) : null;
  const effects =
    confirming === 'contain'
      ? containEffects(view.enforcement_delay_seconds)
      : confirming === 'release'
        ? releaseEffects(view.release_delay_seconds)
        : repeatEffects(sweepCounts(view).scheduled > 0 || retrySweeps);
  // The API does nothing for a contain that comes too soon. The button is not held back for
  // that, so the confirmation says it before a reason is asked for.
  const tooSoonCaveat = confirming === 'repeat' && repeatMayComeTooSoon(view, clock);
  // Two agents can carry one name, so the confirmation also names the tenant and the account.
  const context = agentContext(agent, resolveTenantName(agent.tenant_id, user?.tenants));
  const named = context ? `${agent.name} (${context})` : agent.name;
  const hasReason = reason.trim() !== '';

  return (
    <div className="space-y-5">
      <section aria-labelledby="containment-state" className={`rounded-xl border p-5 ${stateView.cls}`}>
        <h2 id="containment-state" className="text-base font-semibold text-slate-900">{stateView.heading}</h2>
        <p className="text-sm text-slate-800 mt-1">{stateView.body}</p>
        {/* What the API says about a state it knows, for example a statement that does not deny invocation. */}
        {stateView.note && <p className="mt-2 text-sm font-medium text-amber-900">{stateView.note}</p>}
        {state === 'contained' && !view.contained_by_label && !view.contained_at && !stateView.note && (
          <p className="mt-2 text-sm text-slate-800">{OTHER_MEANS_NOTE}</p>
        )}
        {state === 'contained' && !incident && view.contained_at && (
          <p className="mt-2 text-sm text-slate-900">Contained since {formatDate(view.contained_at)}.</p>
        )}
        {/* The sessions of a contained agent: part of the state, so every role reads it. */}
        {sessions.quiet && <p className="mt-2 text-sm font-medium text-slate-900">{sessions.quiet}</p>}
        {sessions.partial && <p className="mt-2 text-sm font-medium text-amber-900">{PARTIAL_NOTE}</p>}
        {sessions.sweeps && (
          <p className="mt-2 text-sm text-slate-800">
            {sessions.sweeps}
            {watching ? ` This is read again every ${SWEEP_POLL_SECONDS} seconds.` : ''}
          </p>
        )}
        {sweeps.length > 0 && (
          <ul aria-label="Background sweeps so far" className="mt-1 space-y-0.5 text-xs text-slate-700">
            {sweeps.map((sweep) => (
              <li key={sweep.key}>
                {sweep.label}, {formatDate(sweep.at)}: {sweep.counts ? `${sweep.counts}. ` : ''}
                {sweep.outcome}.
              </li>
            ))}
          </ul>
        )}
        {sessions.unconfirmed && <p className="mt-2 text-sm font-medium text-amber-900">{SWEEPS_UNCONFIRMED_NOTE}</p>}
        {sessions.overdue && <p className="mt-2 text-sm font-medium text-amber-900">{SWEEPS_OVERDUE_NOTE}</p>}
        {state === 'contained' && incident && (view.contained_by_label || view.contained_at) && (
          <dl className="mt-3 grid grid-cols-1 sm:grid-cols-3 gap-x-8 gap-y-3 text-sm">
            <div>
              <dt className="text-xs font-medium text-slate-700">Contained by</dt>
              <dd className="text-slate-900 break-words">{view.contained_by_label || 'Not recorded'}</dd>
            </div>
            <div>
              <dt className="text-xs font-medium text-slate-700">When</dt>
              <dd className="text-slate-900">{formatDate(view.contained_at, 'Not recorded')}</dd>
            </div>
            <div>
              <dt className="text-xs font-medium text-slate-700">Reason</dt>
              <dd className="text-slate-900"><Reason text={view.reason} /></dd>
            </div>
          </dl>
        )}
      </section>

      {last && (
        <section
          aria-label="Result of the last action"
          className={`rounded-xl border p-4 ${lastPartial ? 'border-amber-300 bg-amber-50' : 'border-emerald-200 bg-emerald-50'}`}
          role="status"
        >
          <p className="text-sm font-semibold text-slate-900">{resultHeadline(last.action, last.result, last.repeat)}</p>
          <StepList steps={lastSteps} />
          {lastSessions && <p className="text-sm text-slate-800 mt-2">Sessions: {lastSessions}</p>}
          <p className="text-sm text-slate-700 mt-2">Nothing was deleted from the agent, its configuration or its data.</p>
          {last.result.audit_complete === false && (
            <p className="text-sm text-amber-900 mt-2">
              {AUDIT_INCOMPLETE_NOTE} Reference: <span className="font-mono break-all">{last.result.request_id}</span>
            </p>
          )}
        </section>
      )}

      <ActionFailurePanel failure={failure} onRefresh={refresh} />
      {failure && failedSteps.length > 0 && (
        <section aria-label="What was and was not done" className={`${CARD} p-4`}>
          <h3 className="text-sm font-semibold text-slate-900">What was and was not done</h3>
          <StepList steps={failedSteps} />
          <p className="text-sm text-slate-700 mt-2">The state shown above was read again after the failure.</p>
        </section>
      )}

      {offered.note && !offered.releaseBlocked && (
        <p className="text-sm text-amber-900 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2" role="status">
          {offered.note}
        </p>
      )}

      {!confirming && (offered.contain || offered.release || (offerRepeat && !repeatWait)) && (
        <div className="flex flex-wrap items-center gap-3">
          {offered.contain && (
            <button type="button" className={DANGER} onClick={() => open('contain')}>
              Contain agent
            </button>
          )}
          {offered.release && (
            <button type="button" className={PRIMARY} onClick={() => open('release')}>
              Release agent
            </button>
          )}
          {/* Sessions may be left: the contain can be sent again. It is not held back for sweeps that have yet to report. */}
          {offerRepeat && !repeatWait && (
            <button type="button" className={SECONDARY} onClick={() => open('repeat')}>
              Stop remaining sessions
            </button>
          )}
        </div>
      )}

      {/* The remedy applies but would do nothing yet: shown, visibly unavailable, with the reason beside it. */}
      {repeatWait && confirming !== 'repeat' && (
        <div className="flex flex-wrap items-center gap-3">
          <button type="button" className={SECONDARY} disabled aria-describedby="repeat-unavailable">
            Stop remaining sessions
          </button>
          <p id="repeat-unavailable" className="text-sm text-slate-800">{repeatWait}</p>
        </div>
      )}

      {/* The two-person rule: Release is shown, visibly unavailable, with the reason beside it. */}
      {offered.releaseBlocked && (
        <div className="flex flex-wrap items-center gap-3">
          <button type="button" className={PRIMARY} disabled aria-describedby="release-unavailable">
            Release agent
          </button>
          <p id="release-unavailable" className="text-sm text-slate-800">{SAME_PERSON_NOTE}</p>
        </div>
      )}

      {confirming && (
        <section aria-labelledby="containment-confirm" className={`${CARD} p-5`}>
          <h2 id="containment-confirm" className="text-sm font-semibold text-slate-900 break-words">
            {CONFIRM[confirming].question(named)}
          </h2>
          <p className="text-sm text-slate-800 mt-2">This is what will happen:</p>
          <ul className="mt-1 list-disc list-inside text-sm text-slate-800 space-y-0.5">
            {effects.map((effect) => (
              <li key={effect}>{effect}</li>
            ))}
          </ul>
          {tooSoonCaveat && <p id="repeat-too-soon" className="text-sm text-slate-800 mt-2">{REPEAT_TOO_SOON_CAVEAT}</p>}
          <label htmlFor="containment-reason" className="block text-sm font-medium text-slate-800 mt-4">
            Reason <span className="text-slate-600 font-normal">(required)</span>
          </label>
          <textarea
            id="containment-reason"
            rows={3}
            maxLength={1000}
            className="mt-1 w-full px-3 py-2 text-sm rounded-lg border border-slate-400 bg-white"
            value={reason}
            aria-required
            aria-describedby="containment-reason-hint"
            onChange={(e) => setReason(e.target.value)}
          />
          <p id="containment-reason-hint" className="text-xs text-slate-600 mt-1">
            The reason is recorded in the audit trail. The button is available once a reason is entered.
          </p>
          <div className="flex gap-2 mt-3">
            <button
              type="button"
              className={CONFIRM[confirming].cls}
              disabled={busy || !hasReason}
              aria-describedby={tooSoonCaveat ? 'containment-reason-hint repeat-too-soon' : 'containment-reason-hint'}
              onClick={() => void run()}
            >
              {busy ? 'Working…' : CONFIRM[confirming].button}
            </button>
            <button type="button" className={SECONDARY} disabled={busy} onClick={() => setConfirming(null)}>
              Cancel
            </button>
          </div>
        </section>
      )}

      <section aria-labelledby="containment-history">
        <h2 id="containment-history" className="text-sm font-semibold text-slate-900 mb-2">History</h2>
        {!incident ? (
          // Not an empty history: one that this role is not shown. One muted line, and no table.
          <p className="text-sm text-slate-600">{INCIDENT_RECORD_NOTE}</p>
        ) : rows.length === 0 ? (
          <div className={`${CARD} p-5 text-sm text-slate-600`}>No containment or release of this agent has been recorded.</div>
        ) : (
          // Nothing in this table takes focus, so the region does: it can scroll sideways on a narrow screen.
          <div className={`${CARD} overflow-x-auto`} tabIndex={0} role="region" aria-label="History entries">
            <table className="w-full text-sm">
              <thead className={TABLE_HEAD}>
                <tr>
                  <th scope="col" className={TH}>When</th>
                  <th scope="col" className={TH}>Who</th>
                  <th scope="col" className={TH}>Action</th>
                  <th scope="col" className={TH}>Outcome</th>
                  <th scope="col" className={TH}>Reason</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {rows.map((row) => {
                  const outcome = outcomeView(row.outcome);
                  // A background sweep is the portal's own act, not a person's decision: its row is
                  // quieter (smaller, muted, no outcome chip) than a contain or a release.
                  const quiet = row.action === 'sweep';
                  const tone = quiet ? 'text-xs text-slate-600' : 'text-slate-700';
                  return (
                    <tr key={row.key} className="align-top">
                      <td className={`${TD} ${tone} whitespace-nowrap`}>{formatDate(row.at)}</td>
                      <td className={`${TD} ${tone} break-words min-w-[11rem]`}>
                        {row.actor || <span className="text-slate-600">Not recorded</span>}
                        {row.role && <span className="block text-xs text-slate-600">{row.role}</span>}
                      </td>
                      <td className={`${TD} ${tone}`}>{eventActionLabel(row.action)}</td>
                      <td className={`${TD} ${tone} whitespace-nowrap`}>
                        {quiet ? sweepOutcomeLabel(row.outcome) : <Badge cls={`${outcome.cls} whitespace-nowrap`} label={outcome.label} />}
                      </td>
                      <td className={`${TD} ${tone}`}><Reason text={row.reason} /></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        {incident && view.events_truncated === true && <p className="text-xs text-slate-600 mt-2">{HISTORY_TRUNCATED_NOTE}</p>}
      </section>
    </div>
  );
}
