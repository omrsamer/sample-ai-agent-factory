// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { useState } from 'react';
import { Link } from 'react-router-dom';
import type { Agent } from '../api/client';
import { isNotFound } from '../api/client';
import { Badge, CARD, ErrorCard, Loading } from '../components/shared/ui';
import { useAsync } from '../components/shared/useAsync';
import { useUser } from '../contexts/UserContext';
import LifecycleActions, { type LifecycleDone } from './LifecycleActions';
import { RETIRED_NOTE, RETIRED_STATUS, agentAfterRetire, agentAfterReview, agentFromRegistration } from './lifecycleView';
import { registrationsApi, type RegistrationDetail } from './registrationsClient';
import { authoritiesOf, statusView } from './registrationView';

const SECONDARY = 'px-3.5 py-1.5 rounded-lg bg-white border border-slate-300 text-slate-700 text-sm font-medium hover:bg-slate-50';

/**
 * The registration behind a registered agent, on the agent's own page: its status, a link to
 * it, and the two things that can be done after approval (confirm its review, retire it). Part
 * of the governed actions feature. A registered agent's id is its registration's record id.
 */
export default function AgentRegistrationPanel({
  agent,
  onChanged,
}: {
  agent: Agent;
  /** Called after an action with what it has just made true of the agent. */
  onChanged: (fields: Partial<Agent>) => void;
}) {
  const { user } = useUser();
  const who = authoritiesOf(user);
  const { data: loaded, loading, error, cause, reload } = useAsync(() => registrationsApi.get(agent.id), [agent.id], 'Failed to load the registration.', {
    keepPreviousOnReload: true,
  });
  // The registration as read again right after an action. It stands until the next full read.
  const [reread, setReread] = useState<{ after: RegistrationDetail; record: RegistrationDetail } | null>(null);
  const record = reread && reread.after === loaded ? reread.record : loaded;

  if (loading && !record) return <Loading label="Loading the registration…" />;
  // A record that is not an agent governance record has no page here; the agent page says the rest.
  if (isNotFound(cause)) return null;
  if (error || !record || !loaded) {
    return <ErrorCard title="Couldn’t load the registration" message={error ?? 'No data was returned.'} onRetry={reload} />;
  }

  const afterAction = async (done: LifecycleDone) => {
    // What the page knows without asking: the agents API serves these fields from a short cache.
    const known = done.action === 'retire' ? agentAfterRetire() : agentAfterReview(done.nextReviewBy, new Date().toISOString());
    try {
      // The registration is read fresh, so it already holds what the action made true, and
      // under whose recorded name. That is what the agent page then shows.
      const next = await registrationsApi.get(agent.id);
      setReread({ after: loaded, record: next });
      onChanged(agentFromRegistration(next, new Date()) ?? known);
    } catch {
      reload();
      onChanged(known);
    }
  };

  const status = statusView(record.status);
  return (
    <section aria-labelledby="agent-registration" className="space-y-4">
      <div className={`${CARD} p-5`}>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 id="agent-registration" className="text-sm font-semibold text-slate-800">Registration</h2>
            <p className="mt-1 flex flex-wrap items-center gap-2 text-sm text-slate-700">
              <Badge cls={status.cls} label={status.label} />
              {record.record_version && <span>Version {record.record_version}</span>}
            </p>
          </div>
          <Link to={`/registrations/${encodeURIComponent(record.record_id)}`} className={SECONDARY}>
            Open the registration
          </Link>
        </div>
        {record.status === RETIRED_STATUS && <p className="text-sm text-slate-800 mt-3">{RETIRED_NOTE}</p>}
      </div>
      <LifecycleActions
        record={record}
        who={who}
        idPrefix="agent"
        onDone={(done) => void afterAction(done)}
        // A refusal can mean that the record changed under this page: it is read again.
        onRefused={reload}
      />
    </section>
  );
}
