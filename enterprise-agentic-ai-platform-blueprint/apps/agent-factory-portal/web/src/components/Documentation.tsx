// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import { Link } from 'react-router-dom';
import { useFeatures } from '../config/features';
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

const GOVERNED_SCREENS: { to: string; name: string; text: string }[] = [
  { to: '/registrations', name: 'Registrations', text: 'Governance records for agents: draft, submit for approval, and the history of every action on a record.' },
  { to: '/approvals', name: 'Approvals', text: 'Records waiting for a decision, for holders of the approver authority. A submitter cannot decide their own record.' },
];

const RULES: string[] = [
  'Teams consume platform capabilities through code, descriptors and pipelines, not through administrator sessions.',
  'A Workstream cell is changed only by its own pipeline.',
  'Central visibility does not grant central write access. This portal never changes an agent, a tool gateway, a policy or a cell.',
  'The default tool gateway authorises the calling workload with AWS IAM. There are no per-end-user grants in the default profile.',
];

const H2 = 'text-base font-semibold text-slate-900 mb-3';

/** In-app guide: what the portal is, what each screen shows, and the rules it follows. */
export default function Documentation() {
  const { governedActions } = useFeatures();
  const screens = governedActions ? [...SCREENS, ...GOVERNED_SCREENS] : SCREENS;
  return (
    <Page wide={false}>
      <PageHeader
        title="Documentation"
        subtitle={
          governedActions
            ? 'The Agent Factory Portal is the product surface of the Enterprise Agentic AI Platform Blueprint. It shows the fleet and the governance catalog, and records agent registrations and the decisions on them. It deploys and changes nothing in a Workstream cell.'
            : 'The Agent Factory Portal is the product surface of the Enterprise Agentic AI Platform Blueprint. It is read-only here: it shows the fleet and the governance catalog, and offers no action that changes them.'
        }
      />

      <section className="mb-8" aria-labelledby="docs-planes">
        <h2 id="docs-planes" className={H2}>The four planes</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          {PLANES.map((plane) => (
            <div key={plane.name} className={`${CARD} p-5`}>
              <h2 className="text-sm font-semibold text-slate-900">{plane.name}</h2>
              <p className="text-sm text-slate-600 mt-1">{plane.summary}</p>
              <p className="text-xs text-slate-600 mt-3">
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
          {screens.map((screen) => (
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

      {governedActions && (
        <section className="mb-8" aria-labelledby="docs-registrations">
          <h2 id="docs-registrations" className={H2}>Registrations and approvals</h2>
          <div className={`${CARD} p-5 text-sm text-slate-700 space-y-2`}>
            <p>
              A registration is the governance record of an agent: who owns it, what it is for, its risk class and data
              classification, and the runtime, tool gateway and tools it uses. A registrar saves a draft and submits it; an
              approver who did not submit it approves or rejects it with a reason. Every action, including a refused one, is
              kept in the record’s history.
            </p>
            <p>
              Registering or approving a record deploys nothing. Deployment still happens only through the Workload pipeline
              of the owning Workstream cell. On an approved record the runtime, tool gateway, subscribed tools, risk class and
              data classification cannot be edited; a change to any of them needs a new registration.
            </p>
          </div>
        </section>
      )}

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
