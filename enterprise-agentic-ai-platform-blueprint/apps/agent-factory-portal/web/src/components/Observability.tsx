// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import { observabilityApi } from '../api/client';
import ObservabilityDashboard from './governance/observability/ObservabilityDashboard';
import { Loading, Page, PageHeader } from './shared/ui';
import { useAsync } from './shared/useAsync';

/** Fleet-wide traces, cost and token usage, drawn from the API's aggregated metrics. */
export default function Observability() {
  const settings = useAsync(() => observabilityApi.getSettings(), [], 'Failed to read observability settings.');
  // A failed settings read is shown as "not configured" rather than as an error on top of one.
  const configured = !!settings.data?.configured;

  return (
    <Page>
      <PageHeader
        title="Observability"
        subtitle="Traces, cost and token usage across the fleet for a date range. Telemetry is collected by each Workstream cell and aggregated centrally for reading only."
      />
      {settings.loading ? <Loading label="Loading observability…" /> : <ObservabilityDashboard configured={configured} />}
    </Page>
  );
}
