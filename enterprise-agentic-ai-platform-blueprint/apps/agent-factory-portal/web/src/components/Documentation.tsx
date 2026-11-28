// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import { Link } from 'react-router-dom';
import { useFeatures } from '../config/features';
import { operatingRules } from './operatingRules';
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
  { to: '/', name: 'Fleet', text: 'Inventory and risk counts, the agents that need attention first, the health of every Workstream cell, and the agents telemetry observes.' },
  { to: '/agents', name: 'Agents', text: 'One inventory of every agent, registered or only detected, with its state, risk, flags and account, filters and export. Each agent shows its owner group and sponsor, why it has its risk level, tool subscriptions, deployments, traces, cost and release evidence, and offers one evidence document to download for an auditor.' },
  { to: '/tool-gateways', name: 'Tool gateways', text: 'Each gateway’s tools, its Cedar policies and enforcement mode, and the agents subscribed to it. A gateway in an account where the portal has no reader role is listed with what the organization registry detected.' },
  { to: '/access-graph', name: 'Access graph', text: 'Who can reach which agent, and which tool gateways each agent may call.' },
  { to: '/observability', name: 'Observability', text: 'Traces, cost and token usage across the fleet for a date range.' },
  { to: '/release-evidence', name: 'Release evidence', text: 'Evaluation runs and the release-gate result recorded for an agent’s builds.' },
  { to: '/catalog', name: 'Governance catalog', text: 'What the platform has approved: agents, tools, guardrail profiles and models.' },
];

const GOVERNED_SCREENS: { to: string; name: string; text: string }[] = [
  { to: '/registrations', name: 'Registrations', text: 'Governance records for agents: draft, submit for approval, confirm a periodic review, retire, and the history of every action on a record.' },
  { to: '/approvals', name: 'Approvals', text: 'Records waiting for a decision, for holders of the approver authority. A submitter cannot decide their own record.' },
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
            ? 'The Agent Factory Portal is the product surface of the Enterprise Agentic AI Platform Blueprint. It shows the fleet and the governance catalog, records agent registrations, the decisions on them and their reviews, and lets an authorised person contain an agent. It deploys nothing and deletes nothing in a Workstream cell.'
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
          {operatingRules(governedActions).map((rule) => (
            <li key={rule}>{rule}</li>
          ))}
        </ul>
      </section>

      {governedActions && (
        <section className="mb-8" aria-labelledby="docs-registrations">
          <h2 id="docs-registrations" className={H2}>Registrations, reviews and containment</h2>
          <div className={`${CARD} p-5 text-sm text-slate-700 space-y-2`}>
            <p>
              A registration is the governance record of an agent: who owns it, what it is for, its risk class and data
              classification, and the runtime, tool gateway and tools it uses. A registrar saves a draft and submits it; an
              approver who did not submit it approves or rejects it with a reason. Every action is kept in the record’s
              history, and so is the refusal of a person who holds the authority and the record’s tenant. Any other refusal
              is answered with a reference and kept in the service’s log.
            </p>
            <p>
              Registering or approving a record deploys nothing. Deployment still happens only through the Workload pipeline
              of the owning Workstream cell. On an approved record the runtime, tool gateway, subscribed tools, risk class and
              data classification cannot be edited; a change to any of them needs a new registration.
            </p>
            <p>
              An approved registration has a review date. An approver who did not submit the registration confirms the
              review with a reason and the date of the next one, at most 366 days ahead, and no more than once in 24
              hours; the registration itself is not changed. Approving a registration that
              names a review date counts as a review too. The agent’s page and its registration show when it was last
              reviewed, by whom, and when the next review is due.
            </p>
            <p>
              An approver can retire a registration, with a reason. Retiring is permanent: the registration cannot be
              approved, changed or submitted again, and to bring the agent back it is registered again. Retiring removes
              nothing that is deployed. The runtime keeps running until its pipeline removes it, and until then the agent’s
              page says that this is left to do. Once nothing is deployed, nothing is left to do: the agent is shown as
              retired, with no risk level and no flags.
            </p>
            <p>
              Containing an agent, from its Containment tab, denies new invocations and stops running sessions. Neither
              containing nor releasing takes effect at once: the page says how long each can take. Nothing is deleted and it
              is reversible, but the person who contained an agent cannot release it: a different person with the authority
              to release must. Both actions need a reason, which is kept in the history.
            </p>
            <p>
              Sessions that are left after a containment are stopped by background sweeps over the following minutes. The
              tab says how many sweeps have run and since when no session is running. Who contained an agent, why, and the
              history are shown to the security, platform and SRE roles; every other role sees that it is contained and
              since when.
            </p>
          </div>
        </section>
      )}

      <section className="mb-8" aria-labelledby="docs-inventory">
        <h2 id="docs-inventory" className={H2}>Reading the inventory</h2>
        <div className={`${CARD} p-5 text-sm text-slate-700 space-y-2`}>
          <p>
            An agent is <strong>Registered</strong> when it has a registration and is running, <strong>Not registered</strong>
            when a runtime is running that nobody registered, and <strong>Registered, not running</strong> when no runtime was
            detected for it. A runtime is detected by the reader role of a configured cell, by the organization registry, or
            by both.
          </p>
          <p>
            On the Fleet page every agent is counted once as <strong>Approved</strong>, <strong>Awaiting approval</strong>
            (registered, not approved yet), <strong>Not registered</strong> or <strong>Retired</strong> (its registration
            was retired for good); these add up to the total. The Retired count is shown only when there is one.
          </p>
          <p>
            Flags mark what needs attention. <strong>Ownerless</strong>: the registration names no owner group, or one that is
            not in the owner roster. <strong>Review overdue</strong>: the review date has passed. <strong>Inactive</strong>: no
            invocation in the inactivity window. <strong>Contained</strong>: invocations are denied. The agents list can also
            be filtered to those with no approved registration.
          </p>
          <p>
            The owner group is an agent’s accountable owner. The sponsor is the accountable person and is optional.
          </p>
          <p>
            If you hold some tenants and not all of them, the agents list offers <strong>My tenants</strong>, which keeps the
            agents of your tenants. <strong>Download evidence</strong> on an agent’s page saves one JSON document about that
            agent for an auditor: its registration and decisions, reviews, containment, risk, tool gateway policy hashes, the
            latest release, and what could not be read.
          </p>
          <p>
            An agent in an account where the portal has no reader role is still listed, marked <strong>No reader role in this
            account</strong>: its status, activity, policy and containment cannot be read, and each of those panels says so.
            Where a reader role exists and one fact could not be read, that fact is shown as unknown; it is never assumed to
            be clear.
          </p>
          <p>
            The same holds for a tool gateway. One that only the organization registry detected is listed with its account,
            Region, authorizer and protocol. Its tools, its tenant and its policies read <strong>Not readable</strong>: the
            portal does not say that it has no tools or no policy engine, because it does not know.
          </p>
          <p>
            The risk level is the most severe of its reasons, which are listed on the agent’s page. Traces, sessions, topology
            and evaluations live in CloudWatch Omni; the portal links to it and embeds nothing.
          </p>
        </div>
      </section>

      <section aria-labelledby="docs-access">
        <h2 id="docs-access" className={H2}>Signing in and roles</h2>
        <div className={`${CARD} p-5 text-sm text-slate-700 space-y-2`}>
          <p>
            You sign in through the identity provider your organization configured for this deployment. The API decides
            your role and which tenants you can see; groups shown in your profile are for reference only.
          </p>
          <p>
            Account identifiers are masked on screen, in resource names and everywhere else. An account is shown by its
            alias when one is configured. Copying a resource name copies it in full.
          </p>
        </div>
      </section>
    </Page>
  );
}
