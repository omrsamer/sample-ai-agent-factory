// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import type { EvalRun, EvalRunSummary } from '../../../api/client';

/** Pure view logic for release evidence: how an evaluation run and its gate are worded. */

const JUDGE_LABEL: Record<string, string> = {
  'Builtin.GoalSuccessRate': 'Goal success',
  'Builtin.Correctness': 'Correctness',
  'Builtin.Helpfulness': 'Helpfulness',
  'Builtin.ToolSelectionAccuracy': 'Tool selection',
};

export function judgeLabel(id: string): string {
  return Object.prototype.hasOwnProperty.call(JUDGE_LABEL, id) ? JUDGE_LABEL[id] : id.replace(/^Builtin\./, '');
}

/** The build the evidence is about: the image digest when known, else the build tag. */
export function currentBuild(
  runs: { current_digest?: string | null; current_build_tag?: string | null } | null | undefined,
): string | null {
  return runs?.current_digest || runs?.current_build_tag || null;
}

const IMAGE_DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const DIGEST_HEX_SHOWN = 12;

export function shortDigest(digest: string | null | undefined): string | null {
  const value = digest?.trim();
  if (!value) return null;
  if (!IMAGE_DIGEST_RE.test(value)) return value;
  return `sha256:${value.slice('sha256:'.length, 'sha256:'.length + DIGEST_HEX_SHOWN)}…`;
}

export function shortBuildTag(tag: string | null | undefined): string | null {
  const t = tag?.trim();
  if (!t) return null;
  if (/^[0-9a-f]{40}$/.test(t)) return t.slice(0, 7);
  const dash = t.lastIndexOf('-');
  return dash >= 0 && dash < t.length - 1 ? t.slice(dash + 1) : t;
}

function shortIdentity(identity: string | null | undefined): string | null {
  if (!identity) return null;
  return identity.startsWith('sha256:') ? shortDigest(identity) : shortBuildTag(identity);
}

export function buildLabel(
  run: { git_sha?: string | null; digest?: string | null; build_tag?: string | null } | null,
  current?: string | null,
): string | null {
  const d =
    shortBuildTag(run?.build_tag) ?? shortDigest(run?.digest) ?? run?.git_sha?.slice(0, 7) ?? shortIdentity(current);
  return d ? `build ${d}` : null;
}

export function checksText(summary: EvalRunSummary | null | undefined): string | null {
  if (!summary) return null;
  const total = summary.checks_passed + summary.checks_failed;
  if (total === 0) return 'no checks scored';
  return `${summary.checks_passed}/${total} checks passed`;
}

const fmt2 = (n: number) => n.toFixed(2);

/** One line on the judges: the first one below the threshold, or the lowest passing mean. */
export function judgesText(
  summary: EvalRunSummary | null | undefined,
  threshold: number,
): { text: string; ok: boolean } | null {
  if (!summary) return null;
  const entries = Object.entries(summary.judge_means ?? {});
  if (entries.length === 0) return null;
  const failing = entries.filter(([, m]) => m === null || m < threshold);
  if (failing.length > 0) {
    const [id, mean] = failing[0];
    const head = mean === null ? `${judgeLabel(id)} not scored` : `${judgeLabel(id)} ${fmt2(mean)} < ${fmt2(threshold)}`;
    const more = failing.length > 1 ? ` (+${failing.length - 1} more)` : '';
    return { text: head + more, ok: false };
  }
  const [lowId, low] = entries.reduce((a, b) => ((b[1] as number) < (a[1] as number) ? b : a));
  const name = entries.length === 1 ? judgeLabel(lowId) : 'judges';
  return { text: `${name} ${fmt2(low as number)} ≥ ${fmt2(threshold)}`, ok: true };
}

/** A run still marked running after this long is treated as abandoned. */
export const STALE_RUNNING_MS = 2 * 60 * 60 * 1000;

export function isRunActive(run: Pick<EvalRun, 'status' | 'started_at'> | null | undefined, now: number): boolean {
  if (!run || run.status !== 'running') return false;
  const started = Date.parse(run.started_at);
  return Number.isNaN(started) || now - started < STALE_RUNNING_MS;
}

export type GateCardState = 'passed' | 'failed' | 'running' | 'none';

export interface GateCard {
  state: GateCardState;
  headline: string;
  facts: string[];
  detail: string | null;
  reasons: string[];
  regressions: string[];
}

/** The release-gate summary for the current build. Only a run whose gate passed reads as passed. */
export function gateCard(input: {
  currentBuild: string | null | undefined;
  currentRun: EvalRun | null | undefined;
  now: number;
}): GateCard {
  const { currentBuild, currentRun: run, now } = input;
  const build = buildLabel(run ?? null, currentBuild);
  const withBuild = (facts: (string | null | undefined)[]) => [...facts, build].filter(Boolean) as string[];
  if (!currentBuild) {
    return {
      state: 'none',
      headline: 'No build to evaluate yet',
      facts: [],
      detail: 'Evidence appears once the pipeline has built this agent and run its evaluation stage.',
      reasons: [],
      regressions: [],
    };
  }
  if (!run || (run.status === 'running' && !isRunActive(run, now))) {
    return {
      state: 'none',
      headline: run ? 'The last run stopped responding' : 'Not evaluated yet',
      facts: withBuild([]),
      detail: 'No completed evaluation run exists for this build, so its release gate has not passed.',
      reasons: [],
      regressions: [],
    };
  }
  if (run.status === 'running') {
    const n = run.item_count ?? 0;
    return {
      state: 'running',
      headline: 'Evaluating',
      facts: withBuild([n > 0 ? `${n} ${n === 1 ? 'item' : 'items'}` : null]),
      detail: 'The pipeline is evaluating this build. Reload to see the result.',
      reasons: [],
      regressions: [],
    };
  }
  const threshold = run.config?.gate?.judge_min_mean ?? 0;
  const facts = withBuild([checksText(run.summary), judgesText(run.summary, threshold)?.text]);
  const regressions = run.regressions ?? [];
  if (run.gate?.passed) {
    return { state: 'passed', headline: 'Release gate passed', facts, detail: null, reasons: [], regressions };
  }
  return {
    state: 'failed',
    headline: run.status === 'error' ? 'The run errored before the gate could pass' : 'Release gate failed',
    facts,
    detail: 'Promotion of this build is blocked until a run passes or an approver records an override.',
    reasons: run.gate?.reasons ?? [],
    regressions,
  };
}

const RUN_LABEL_MINUTE: Intl.DateTimeFormatOptions = { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' };
const RUN_LABEL_SECOND: Intl.DateTimeFormatOptions = { ...RUN_LABEL_MINUTE, second: '2-digit' };

/** A start-time label per run, with seconds added only where two runs share a minute. */
export function runLabels(
  runs: readonly Pick<EvalRun, 'run_id' | 'started_at'>[],
  locale?: string,
): Map<string, string> {
  const fmt = (iso: string, opts: Intl.DateTimeFormatOptions) => {
    const d = new Date(iso);
    return Number.isNaN(d.getTime()) ? 'Run' : d.toLocaleString(locale, opts);
  };
  const minute = runs.map((r) => fmt(r.started_at, RUN_LABEL_MINUTE));
  const count = new Map<string, number>();
  for (const m of minute) count.set(m, (count.get(m) ?? 0) + 1);
  return new Map(
    runs.map((r, i) => [r.run_id, (count.get(minute[i]) ?? 0) > 1 ? fmt(r.started_at, RUN_LABEL_SECOND) : minute[i]]),
  );
}
