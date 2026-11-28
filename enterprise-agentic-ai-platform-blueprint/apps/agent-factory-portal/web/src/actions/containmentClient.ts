// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import client from '../api/client';
import type { AuditEvent } from './registrationsClient';

/**
 * Containment requests: reading an agent's containment state and history, and the two writes
 * that contain and release it. Like the registrations client, this module is reachable only
 * through a screen that the application loads when `features.governedActions` is true.
 *
 * Containing an agent denies every invocation of its runtime and stops its running sessions.
 * It deletes nothing and is reversible. The contract is `../api/CONTAINMENT_CONTRACT.md`.
 */

/** `GET /agents/{id}/containment`. */
export interface ContainmentView {
  agent_id: string;
  /** `contained`, `not_contained` or `unknown`. Anything else is treated as unknown. */
  state: string;
  /** Null when the agent has no runtime, so there is nothing to contain. */
  runtime_arn?: string | null;
  /** False when no cell in the agent's account has given the portal the authority to contain it. */
  enabled?: boolean;
  /**
   * A sentence to show with the state. Why it is unknown; or, with a known state, something the
   * reader must know about it: a statement that carries the portal's identifier but does not
   * deny invocation (the agent is not contained), or that who contained the agent could not be
   * established.
   */
  detail?: string | null;
  /**
   * Who contained the agent. Part of the incident record, which the API sends only to a caller
   * whose role can contain or release; null for anyone else, and for an agent contained by other
   * means than the portal.
   */
  contained_by_label?: string | null;
  /** Sent to every role. Null for an agent contained by other means than the portal. */
  contained_at?: string | null;
  /** Why it was contained. Part of the incident record, like `contained_by_label`. */
  reason?: string | null;
  /** True when the caller contained the agent and so may not release it. */
  contained_by_me?: boolean;
  /** True when the contain request that holds did not stop every session it found. It does not change afterwards. */
  partial?: boolean;
  /**
   * The background sweeps of the containment that holds: how many it scheduled and how many of
   * those have run, whatever their outcome. They run after the request, for up to 15 minutes.
   */
  sweeps?: ContainmentSweeps | null;
  /**
   * Since when no session the portal can find is running: the end of the first complete sweep
   * that started after every host applied the deny. Null until such a sweep has run.
   */
  quiet_at?: string | null;
  /** How long a contain can take to apply everywhere, in seconds. */
  enforcement_delay_seconds?: number | null;
  /** How long a release can take to apply everywhere, in seconds. It is longer than a contain. */
  release_delay_seconds?: number | null;
  /**
   * The audit trail of contain and release attempts and of background sweeps, newest first. Part
   * of the incident record: empty for a caller whose role can neither contain nor release.
   */
  events?: AuditEvent[] | null;
  /** True when the history holds older events than the ones listed. */
  events_truncated?: boolean;
}

export interface ContainmentSweeps {
  scheduled?: number | null;
  done?: number | null;
}

/** One step of a contain or release, in the server's words. */
export interface ContainmentStep {
  /** `policy`, `verify`, `sessions`, or `background` for the sweeps a contain schedules. */
  id: string;
  label: string;
  /**
   * `done`, `unchanged`, `partial`, `failed`, `skipped`, or `scheduled` for the background sweeps
   * a contain leaves behind. Shown as recorded when unknown.
   */
  status: string;
  detail?: string | null;
}

/** What happened to the sessions that were running when the agent was contained. */
export interface SessionsStopped {
  /**
   * `ok` when both sources of session ids were read; `ok; <what was incomplete>` when one could
   * not be; anything else says why the sessions could not be listed or stopped.
   */
  discovery: string;
  /** Where the sessions were found, before duplicates were removed. */
  sources?: { spans?: number; log_streams?: number } | null;
  /** Distinct sessions. */
  found?: number;
  stopped?: number;
  not_active?: number;
  failed?: number;
  /** The time limit ran out before these were tried. */
  not_attempted?: number;
  /** Error codes of the stops that failed. */
  stop_errors?: string[] | null;
}

/** The answer to a contain or release request. */
export interface ContainmentResult {
  action: string;
  /** `allowed`, or `unchanged` when the agent was already in the requested state. */
  outcome: string;
  /** The caller's reason followed by what was done. */
  reason?: string;
  request_id: string;
  agent_id?: string;
  runtime_arn?: string;
  /** The state after the action, verified by reading the policy back. */
  state: string;
  changed?: boolean;
  /**
   * Contain only: a statement with the portal's identifier that the portal had not written was
   * in the policy and was replaced. The policy step says so in words.
   */
  replaced_foreign_statement?: boolean;
  /** Release only: the policy held nothing else and was deleted. The steps say so in words. */
  policy_deleted?: boolean;
  /** Statements in the policy that are not the portal's. They are never touched. */
  other_statements_kept?: number;
  /** Contain only: the invoke actions the statement denies. The steps say so in words. */
  denied_actions?: string[] | null;
  /** Contain only. */
  sessions?: SessionsStopped | null;
  /** What was done, in order. */
  steps?: ContainmentStep[] | null;
  /**
   * True when the agent is contained but the session step did not fully complete, or the
   * background sweeps could not be scheduled.
   */
  partial?: boolean;
  /** How long the action this result reports can take to apply everywhere, in seconds. */
  enforcement_delay_seconds?: number | null;
  /** Contain only: the delay of each background sweep it scheduled, in seconds. The steps say so in words. */
  sweeps_scheduled_in_seconds?: number[] | null;
  /**
   * Contain only, with outcome `unchanged`: set when the agent was contained a moment ago and
   * this request therefore did nothing (no session was stopped, nothing was scheduled). It says
   * in how many seconds a contain does its work again.
   */
  retry_after_seconds?: number | null;
  audit_complete?: boolean;
}

const path = (agentId: string, suffix = '') => `/agents/${encodeURIComponent(agentId)}/containment${suffix}`;

/** `runtimeArn` is sent for an agent that has no registration, so the server knows which runtime is meant. */
function body(reason: string, runtimeArn?: string | null): { reason: string; runtime_arn?: string } {
  return runtimeArn ? { reason, runtime_arn: runtimeArn } : { reason };
}

export const containmentApi = {
  get: async (agentId: string): Promise<ContainmentView> => (await client.get<ContainmentView>(path(agentId))).data,
  contain: async (agentId: string, reason: string, runtimeArn?: string | null): Promise<ContainmentResult> =>
    (await client.post<ContainmentResult>(path(agentId, '/contain'), body(reason, runtimeArn))).data,
  release: async (agentId: string, reason: string, runtimeArn?: string | null): Promise<ContainmentResult> =>
    (await client.post<ContainmentResult>(path(agentId, '/release'), body(reason, runtimeArn))).data,
};
