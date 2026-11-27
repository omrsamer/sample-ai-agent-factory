// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import { describe, expect, it } from 'vitest';
import type { EvalRun } from '../../../api/client';
import tabSrc from './EvaluationsTab.tsx?raw';
import {
  STALE_RUNNING_MS,
  buildLabel,
  checksText,
  currentBuild,
  gateCard,
  isRunActive,
  judgeLabel,
  judgesText,
  runLabels,
  shortBuildTag,
  shortDigest,
} from './evaluationsLogic';

const NOW = Date.parse('2026-03-01T12:00:00Z');
const DIGEST = `sha256:${'ab'.repeat(32)}`;

const run = (over: Partial<EvalRun> = {}): EvalRun => ({
  run_id: 'run-1',
  repo_id: 'repo-1',
  agent_id: 'agent-1',
  project_id: 'project-1',
  stage: 'nonprod',
  trigger: 'auto',
  started_by: 'pipeline',
  started_at: '2026-03-01T11:00:00Z',
  status: 'passed',
  config: {
    version: 1,
    dataset: 'evals/dataset.jsonl',
    checks: { tools: 'in_order', args: 'subset', no_error: true },
    judges: ['Builtin.Correctness'],
    gate: { checks: 'all_pass', judge_min_mean: 0.8 },
  },
  summary: { items: 4, checks_passed: 12, checks_failed: 0, judge_means: { 'Builtin.Correctness': 0.9 } },
  gate: { passed: true, reasons: [] },
  ...over,
});

describe('labels', () => {
  it('names built-in judges and strips the prefix from unknown ones', () => {
    expect(judgeLabel('Builtin.Correctness')).toBe('Correctness');
    expect(judgeLabel('Builtin.Custom')).toBe('Custom');
    expect(judgeLabel('team.judge')).toBe('team.judge');
  });

  it('shortens digests, commit ids and build tags', () => {
    expect(shortDigest(DIGEST)).toBe('sha256:abababababab…');
    expect(shortDigest('not-a-digest')).toBe('not-a-digest');
    expect(shortBuildTag('0123456789abcdef0123456789abcdef01234567')).toBe('0123456');
    expect(shortBuildTag('main-42')).toBe('42');
    expect(buildLabel({ build_tag: 'main-42' })).toBe('build 42');
    expect(buildLabel(null, DIGEST)).toBe('build sha256:abababababab…');
    expect(buildLabel(null, null)).toBeNull();
  });

  it('prefers the digest as the current build', () => {
    expect(currentBuild({ current_digest: DIGEST, current_build_tag: 'main-42' })).toBe(DIGEST);
    expect(currentBuild({ current_digest: null, current_build_tag: 'main-42' })).toBe('main-42');
    expect(currentBuild(null)).toBeNull();
  });
});

describe('checksText and judgesText', () => {
  it('summarises checks', () => {
    expect(checksText({ items: 1, checks_passed: 3, checks_failed: 1, judge_means: {} })).toBe('3/4 checks passed');
    expect(checksText({ items: 0, checks_passed: 0, checks_failed: 0, judge_means: {} })).toBe('no checks scored');
    expect(checksText(null)).toBeNull();
  });

  it('reports the first judge below the threshold, or the lowest passing mean', () => {
    const summary = (judge_means: Record<string, number | null>) => ({ items: 1, checks_passed: 1, checks_failed: 0, judge_means });
    expect(judgesText(summary({ 'Builtin.Correctness': 0.9 }), 0.8)).toEqual({ text: 'Correctness 0.90 ≥ 0.80', ok: true });
    expect(judgesText(summary({ 'Builtin.Correctness': 0.5, 'Builtin.Helpfulness': null }), 0.8)).toEqual({
      text: 'Correctness 0.50 < 0.80 (+1 more)',
      ok: false,
    });
    expect(judgesText(summary({ 'Builtin.Helpfulness': null }), 0.8)?.text).toBe('Helpfulness not scored');
    expect(judgesText(summary({}), 0.8)).toBeNull();
  });
});

describe('isRunActive', () => {
  it('is true only for a running run that started recently', () => {
    expect(isRunActive(run({ status: 'running' }), NOW)).toBe(true);
    expect(isRunActive(run({ status: 'passed' }), NOW)).toBe(false);
    expect(isRunActive(run({ status: 'running', started_at: new Date(NOW - STALE_RUNNING_MS - 1).toISOString() }), NOW)).toBe(false);
    expect(isRunActive(null, NOW)).toBe(false);
  });
});

describe('gateCard', () => {
  it('reads as passed only when the gate itself passed', () => {
    const card = gateCard({ currentBuild: DIGEST, currentRun: run(), now: NOW });
    expect(card.state).toBe('passed');
    expect(card.headline).toBe('Release gate passed');
    expect(card.facts).toEqual(['12/12 checks passed', 'Correctness 0.90 ≥ 0.80', 'build sha256:abababababab…']);
  });

  it('is failed when the run passed its checks but the gate did not', () => {
    const card = gateCard({
      currentBuild: DIGEST,
      currentRun: run({ status: 'failed', gate: { passed: false, reasons: ['Correctness below 0.80'] }, regressions: ['latency'] }),
      now: NOW,
    });
    expect(card.state).toBe('failed');
    expect(card.reasons).toEqual(['Correctness below 0.80']);
    expect(card.regressions).toEqual(['latency']);
  });

  it('is failed, not passed, when a passed-status run carries no gate result', () => {
    expect(gateCard({ currentBuild: DIGEST, currentRun: run({ gate: null }), now: NOW }).state).toBe('failed');
  });

  it('says so when a run errored', () => {
    const card = gateCard({ currentBuild: DIGEST, currentRun: run({ status: 'error', gate: null, summary: null }), now: NOW });
    expect(card.state).toBe('failed');
    expect(card.headline).toMatch(/errored/);
  });

  it('is none when there is no build, no run, or only an abandoned run', () => {
    expect(gateCard({ currentBuild: null, currentRun: run(), now: NOW }).headline).toBe('No build to evaluate yet');
    expect(gateCard({ currentBuild: DIGEST, currentRun: null, now: NOW }).headline).toBe('Not evaluated yet');
    const stale = run({ status: 'running', started_at: new Date(NOW - STALE_RUNNING_MS - 1).toISOString() });
    expect(gateCard({ currentBuild: DIGEST, currentRun: stale, now: NOW }).headline).toBe('The last run stopped responding');
  });

  it('is running for an active run', () => {
    const card = gateCard({ currentBuild: DIGEST, currentRun: run({ status: 'running', item_count: 3 }), now: NOW });
    expect(card.state).toBe('running');
    expect(card.facts[0]).toBe('3 items');
  });

  it('tolerates a run without a gate configuration', () => {
    const bare = run({ config: undefined as never, gate: { passed: true, reasons: [] } });
    expect(() => gateCard({ currentBuild: DIGEST, currentRun: bare, now: NOW })).not.toThrow();
  });
});

describe('runLabels', () => {
  it('adds seconds only where two runs share a minute', () => {
    const labels = runLabels(
      [
        { run_id: 'a', started_at: '2026-03-01T11:00:05Z' },
        { run_id: 'b', started_at: '2026-03-01T11:00:40Z' },
        { run_id: 'c', started_at: '2026-03-01T12:30:00Z' },
      ],
      'en-GB',
    );
    expect(labels.get('a')).not.toBe(labels.get('b'));
    expect(labels.get('a')).toMatch(/:05/);
    expect(labels.get('c')).not.toMatch(/:00:00/);
  });

  it('labels an unparseable start time without throwing', () => {
    expect(runLabels([{ run_id: 'x', started_at: 'not a date' }]).get('x')).toBe('Run');
  });
});

describe('the Release evidence tab', () => {
  it('reads the agent-scoped runs and offers no way to start a run or override a gate', () => {
    expect(tabSrc).toMatch(/agentOpsApi\.evalRuns\(/);
    expect(tabSrc).not.toMatch(/<button|onClick|<form|<input/);
  });
});
