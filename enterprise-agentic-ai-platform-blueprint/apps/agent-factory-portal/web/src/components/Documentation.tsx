// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import { Link } from 'react-router-dom';
import { CARD, Page, PageHeader } from './shared/ui';

interface PlaneDoc {
  name: string;
  summary: string;
  inPortal: string;
}

const PLANES: PlaneDoc[] = [
  {
    name: 'Developer experience',
    summary: 'Versioned agent templates, CLI and repository workflows, approved extension points and self-service onboarding.',
    inPortal: 'Not in this milestone. Teams work through their repository and pipeline.',
  },
  {
    name: 'Platform control',
    summary: 'Registry governance, model and guardrail policy, shared inference, release orchestration and reusable account baselines.',
    inPortal: 'Governance catalog: agents, tools, guardrail profiles and approved models.',
  },
  {
    name: 'Workstream execution',
    summary: 'Isolated cells that hold a team’s runtime, memory, tool gateway, tools and application data.',
    inPortal: 'Shown through the fleet, agent and tool gateway views. Cells are never changed from here.',
  },
  {
    name: 'Assurance and operations',
    summary: 'Organization policy, evidence gates, fleet telemetry, audit, incident response, quota management and chargeback.',
    inPortal: 'Fleet, Agents, Tool gateways, Access graph, Observability and Release evidence.',
  },
];

const SCREENS: { to: string; name: string; text: string }[] = [
  { to: '/', name: 'Fleet', text: 'Counts, the health of every Workstream cell, and recently added agents.' },
  { to: '/agents', name: 'Agents', text: 'Every agent, with its ownership, tool subscriptions, deployments, traces, cost and release evidence.' },
  { to: '/tool-gateways', name: 'Tool gateways', text: 'Each gateway’s tools, its Cedar policies and enforcement mode, and the agents subscribed to it.' },
  { to: '/access-graph', name: 'Access graph', text: 'Who can reach which agent, and which tool gateways each agent may call.' },
  { to: '/observability', name: 'Observability', text: 'Traces, cost and token usage across the fleet for a date range.' },
  { to: '/release-evidence', name: 'Release evidence', text: 'Evaluation runs and the release-gate result recorded for an agent’s builds.' },
  { to: '/catalog', name: 'Governance catalog', text: 'What the platform has approved: agents, tools, guardrail profiles and models.' },
];

const RULES: string[] = [
  'Teams consume platform capabilities through code, descriptors and pipelines, not through administrator sessions.',
  'A Workstream cell is changed only by its own pipeline.',
  'Central visibility does not grant central write access. This portal reads; it does not change what it shows.',
  'The default tool gateway authorises the calling workload with AWS IAM. There are no per-end-user grants in the default profile.',
];

const H2 = 'text-base font-semibold text-slate-900 mb-3';

/** In-app guide: what the portal is, what each screen shows, and the rules it follows. */
export default function Documentation() {
  return (
    <Page wide={false}>
      <PageHeader
        title="Documentation"
        subtitle="The Agent Factory Portal is the product surface of the Enterprise Agentic AI Platform Blueprint. This milestone is read-only: it shows the fleet and the governance catalog, and offers no action that changes them."
      />

      <section className="mb-8" aria-labelledby="docs-planes">
        <h2 id="docs-planes" className={H2}>The four planes</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          {PLANES.map((plane) => (
            <div key={plane.name} className={`${CARD} p-5`}>
              <h3 className="text-sm font-semibold text-slate-900">{plane.name}</h3>
              <p className="text-sm text-slate-600 mt-1">{plane.summary}</p>
              <p className="text-xs text-slate-500 mt-3">
                <span className="font-medium text-slate-700">In the portal: </span>
                {plane.inPortal}
              </p>
            </div>
          ))}
        </div>
      </section>

      <section className="mb-8" aria-labelledby="docs-screens">
        <h2 id="docs-screens" className={H2}>What each screen shows</h2>
        <dl className={`${CARD} divide-y divide-slate-100`}>
          {SCREENS.map((screen) => (
            <div key={screen.to} className="px-5 py-3 sm:grid sm:grid-cols-4 sm:gap-4">
              <dt className="text-sm font-medium">
                <Link to={screen.to} className="text-blue-700 hover:underline">{screen.name}</Link>
              </dt>
              <dd className="text-sm text-slate-600 sm:col-span-3 mt-0.5 sm:mt-0">{screen.text}</dd>
            </div>
          ))}
        </dl>
      </section>

      <section className="mb-8" aria-labelledby="docs-rules">
        <h2 id="docs-rules" className={H2}>Operating rules</h2>
        <ul className={`${CARD} p-5 space-y-2 list-disc list-inside text-sm text-slate-700`}>
          {RULES.map((rule) => (
            <li key={rule}>{rule}</li>
          ))}
        </ul>
      </section>

      <section aria-labelledby="docs-access">
        <h2 id="docs-access" className={H2}>Signing in and roles</h2>
        <div className={`${CARD} p-5 text-sm text-slate-700 space-y-2`}>
          <p>
            You sign in through the identity provider your organization configured for this deployment. The API decides
            your role and which tenants you can see; groups shown in your profile are for reference only.
          </p>
          <p>
            Account identifiers in resource names are masked on screen. Copying a value copies it in full.
          </p>
        </div>
      </section>
    </Page>
  );
}
