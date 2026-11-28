// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { Link } from 'react-router-dom';
import { agentsApi } from '../api/client';
import { RETIRED_FOLLOW_UP, RETIRED_LIFECYCLE, retiredRuntimeReason } from '../components/governance/inventory';
import { useAsync } from '../components/shared/useAsync';

/**
 * On a retired registration: whether its agent's runtime is still deployed, which is the
 * follow-up the owner must do. The registration does not say; the agent does, so the agent is
 * read (a registered agent's id is its registration's record id). When there is no such agent,
 * it cannot be read, or no runtime is detected, nothing is added.
 */
export default function RetiredFollowUp({ recordId }: { recordId: string }) {
  const { data: agent } = useAsync(() => agentsApi.get(recordId), [recordId], 'Failed to load the agent.');
  if (!agent) return null;
  // The registration was read fresh and is retired, whatever lifecycle the agent's cached record still carries.
  const reason = retiredRuntimeReason({ ...agent, lifecycle_state: RETIRED_LIFECYCLE });
  if (!reason) return null;
  return (
    <div id="registration-still-deployed" className="mt-3 rounded-lg border border-amber-300 bg-amber-50 px-3 py-2">
      <p className="text-sm font-medium text-slate-900">{reason}</p>
      <p className="text-sm text-slate-800 mt-1">{RETIRED_FOLLOW_UP}</p>
      <p className="text-sm mt-1">
        <Link to={`/agents/${encodeURIComponent(agent.id)}`} className="text-blue-700 hover:underline">
          Open the agent
        </Link>
      </p>
    </div>
  );
}
