// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import { useMemo, useState } from 'react';
import { agentOpsApi, isNotFound } from '../../../api/client';
import type { EvalRun } from '../../../api/client';
import { useAsync } from '../../shared/useAsync';
import { maskAccountIds } from '../../shared/arnDisplay';
import { formatDate } from '../../shared/ui';
import { currentBuild, gateCard, judgeLabel, runLabels, type GateCardState } from './evaluationsLogic';
import { DataNotes, ObsEmptyCard } from './ObsEmptyCard';

const CARD = 'bg-white/70 backdrop-blur rounded-xl border border-slate-200/60 shadow-sm';
const TH = 'text-left py-2 font-medium';
const RECENT = 10;

const GATE_DOT: Record<GateCardState, string> = {
  passed: 'bg-emerald-500',
  failed: 'bg-amber-500',
  running: 'bg-slate-400',
  none: 'bg-slate-300',
};

const STATUS_CLS: Record<EvalRun['status'], string> = {
  passed: 'bg-emerald-50 text-emerald-700 border-emerald-200',
  failed: 'bg-amber-50 text-amber-700 border-amber-200',
  error: 'bg-amber-50 text-amber-700 border-amber-200',
  running: 'bg-slate-50 text-slate-600 border-slate-200',
};

/**
 * Release evidence for one agent: the gate result for its current build, recent evaluation
 * runs, and any promotion made without a passing run. Read-only; runs are started by the
 * pipeline.
 */
export default function EvaluationsTab({ agentId }: { agentId: string }) {
  const { data: runs, loading, error, cause } = useAsync(
    () => agentOpsApi.evalRuns(agentId),
    [agentId],
    'Failed to load evaluation runs',
  );
  const labels = useMemo(() => runLabels(runs?.runs ?? []), [runs]);
  // Read once per mount: the clock decides whether a still-running run counts as abandoned.
  const [now] = useState(() => Date.now());

  if (loading) {
    return (
      <div className={`${CARD} p-5 flex items-center gap-2 text-xs text-slate-600`} role="status">
        <span className="w-3.5 h-3.5 border-2 border-slate-300 border-t-slate-500 rounded-full animate-spin" aria-hidden="true" />
        Loading…
      </div>
    );
  }
  if (isNotFound(cause)) {
    return (
      <ObsEmptyCard
        title="No release evidence"
        body="No evaluation has been recorded for this agent. Evidence appears once its pipeline runs an evaluation stage."
      />
    );
  }
  if (error || !runs) {
    return <ObsEmptyCard title="Couldn't load release evidence" body={error ?? 'No data was returned.'} tone="amber" />;
  }

  // An agent that belongs to no configured cell has no pipeline. The API says so in a sentence,
  // which is shown as the plain fact it is rather than as a warning above an empty gate.
  const explanations = runs.warnings ?? [];
  if ((runs.runs ?? []).length === 0 && !runs.current_run && explanations.length > 0) {
    return (
      <div className={`${CARD} p-5`}>
        <h2 className="text-sm font-semibold text-slate-900">No release evidence</h2>
        {explanations.map((sentence) => (
          <p key={sentence} className="text-sm text-slate-700 mt-1 max-w-2xl">{sentence}</p>
        ))}
      </div>
    );
  }

  const card = gateCard({ currentBuild: currentBuild(runs), currentRun: runs.current_run, now });
  const recent = (runs.runs ?? []).slice(0, RECENT);
  const overrides = (runs.overrides ?? []).slice(0, RECENT);

  return (
    <div className="space-y-4">
      <DataNotes notes={runs.warnings ?? []} />
      <div className={`${CARD} p-5`}>
        <div className="text-[11px] uppercase tracking-wide text-slate-600 font-medium">Release gate · current build</div>
        <div className="mt-1 flex items-center gap-2">
          <span className={`inline-block h-2.5 w-2.5 rounded-full ${GATE_DOT[card.state]}`} aria-hidden="true" />
          <span className="text-sm font-semibold text-slate-900">{card.headline}</span>
        </div>
        {card.facts.length > 0 && <div className="mt-1 text-xs text-slate-600 tabular-nums">{card.facts.join(' · ')}</div>}
        {card.detail && <p className="mt-1 text-xs text-slate-600">{card.detail}</p>}
        {card.regressions.length > 0 && (
          <div className="mt-1 text-xs text-amber-700">Regression against the baseline: {card.regressions.join('; ')}</div>
        )}
        {card.reasons.length > 0 && (
          <ul className="mt-2 space-y-0.5 text-xs text-amber-700">
            {card.reasons.map((r) => <li key={r}>{r}</li>)}
          </ul>
        )}
      </div>

      <div className={`${CARD} p-5`}>
        <h2 className="text-sm font-semibold text-slate-900 mb-3">Recent runs</h2>
        {recent.length === 0 ? (
          <p className="text-sm text-slate-600">No evaluation has run for this agent yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-[11px] text-slate-600 uppercase tracking-wide border-b border-slate-100">
                  <th scope="col" className={TH}>Started</th>
                  <th scope="col" className={`${TH} pl-4`}>Environment</th>
                  <th scope="col" className={`${TH} pl-4`}>Result</th>
                  <th scope="col" className={`${TH} pl-4`}>Checks</th>
                  <th scope="col" className={`${TH} pl-4`}>Judges (mean)</th>
                  <th scope="col" className={`${TH} pl-4`}>Trigger</th>
                </tr>
              </thead>
              <tbody>
                {recent.map((run) => {
                  const judges = Object.entries(run.summary?.judge_means ?? {});
                  return (
                    <tr key={run.run_id} className="border-b border-slate-50 hover:bg-slate-50/40 align-top">
                      <td className="py-2.5 text-slate-700 whitespace-nowrap tabular-nums" title={`${run.run_id} · ${formatDate(run.started_at)}`}>
                        <time dateTime={run.started_at}>{labels.get(run.run_id) ?? 'Not set'}</time>
                      </td>
                      <td className="py-2.5 pl-4 text-slate-600">{run.stage || 'Not set'}</td>
                      <td className="py-2.5 pl-4">
                        <span className={`inline-flex px-2 py-0.5 rounded-full border text-[11px] font-semibold capitalize ${STATUS_CLS[run.status] ?? STATUS_CLS.running}`}>
                          {run.status}
                        </span>
                      </td>
                      <td className="py-2.5 pl-4 text-slate-600 tabular-nums whitespace-nowrap">
                        {run.summary ? `${run.summary.checks_passed} passed · ${run.summary.checks_failed} failed` : 'None'}
                      </td>
                      <td className="py-2.5 pl-4 text-slate-600 tabular-nums">
                        {judges.length === 0
                          ? 'None'
                          : judges.map(([id, m]) => (
                              <div key={id} className="whitespace-nowrap">
                                {judgeLabel(id)} <span className="text-slate-900 font-medium">{m === null ? 'not scored' : m.toFixed(2)}</span>
                              </div>
                            ))}
                      </td>
                      <td className="py-2.5 pl-4 text-slate-600 capitalize">{run.trigger}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {overrides.length > 0 && (
        <div className={`${CARD} p-5`}>
          <h2 className="text-sm font-semibold text-slate-900">Gate overrides</h2>
          <p className="text-xs text-slate-600 mt-0.5 mb-3">Promotions made without a passing evaluation, with the reason the approver gave.</p>
          <ul className="divide-y divide-slate-100">
            {overrides.map((o) => (
              <li key={`${o.at}-${o.by}`} className="py-2 text-sm">
                <div className="flex flex-wrap items-baseline justify-between gap-2">
                  <span className="font-medium text-slate-800" >{o.by_name || maskAccountIds(o.by)}</span>
                  <span className="text-xs text-slate-600 tabular-nums">{formatDate(o.at)}</span>
                </div>
                <p className="text-slate-600 mt-0.5 break-words">{o.reason}</p>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
