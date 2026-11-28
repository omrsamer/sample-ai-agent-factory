// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import { useState } from 'react';
import { guardrailsApi } from '../../api/client';
import type { GuardrailTemplate } from '../../types';
import { guardrailFeatures, guardrailStatusView } from './guardrailSummary';
import { Badge, CARD, CodeValue, EmptyCard, ErrorCard, Field, Loading, formatDate } from '../shared/ui';
import { useAsync } from '../shared/useAsync';

function ProfileDetail({ templateId }: { templateId: string }) {
  const { data, loading, error, reload } = useAsync(() => guardrailsApi.get(templateId), [templateId], 'Failed to load the guardrail profile.');
  if (loading) return <Loading label="Loading profile…" />;
  if (error || !data) return <ErrorCard title="Couldn’t load the profile" message={error ?? 'No data was returned.'} onRetry={reload} />;
  const features = guardrailFeatures(data);
  return (
    <>
      <div className="flex flex-wrap gap-1.5 mb-4">
        {features.length === 0 ? (
          <span className="text-xs text-slate-600">No protections configured</span>
        ) : (
          features.map((f) => <Badge key={f} cls="bg-slate-100 text-slate-600" label={f} />)
        )}
      </div>
    <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-8 gap-y-4">
      <Field className="sm:col-span-2" label="Guardrail ARN"><CodeValue value={data.guardrail_arn} copyLabel="guardrail ARN" /></Field>
      <Field label="Guardrail version">{data.guardrail_version ?? 'Not set'}</Field>
      <Field label="Updated">{formatDate(data.updated_at)}</Field>
      <Field label="Content filters">
        {(data.content_filters ?? []).length === 0 ? 'None' : (
          <ul className="space-y-0.5">
            {data.content_filters.map((f) => (
              <li key={f.type}>{f.type}: input {f.input_strength}, output {f.output_strength}</li>
            ))}
          </ul>
        )}
      </Field>
      <Field label="Denied topics">
        {(data.denied_topics ?? []).length === 0 ? 'None' : data.denied_topics.map((t) => t.name).join(', ')}
      </Field>
      <Field label="Sensitive information types">
        {(data.pii_entities ?? []).length === 0 ? 'None' : data.pii_entities.map((p) => `${p.type} (${p.action.toLowerCase()})`).join(', ')}
      </Field>
      <Field label="Custom patterns">
        {(data.sensitive_regexes ?? []).length === 0 ? 'None' : data.sensitive_regexes.map((r) => r.name).join(', ')}
      </Field>
      <Field label="Word filters">
        {data.word_filter
          ? `${data.word_filter.enable_profanity ? 'Profanity filter on' : 'Profanity filter off'}, ${data.word_filter.blocked_words?.length ?? 0} blocked words`
          : 'None'}
      </Field>
      <Field label="Contextual grounding">
        {data.contextual_grounding?.enabled
          ? `Grounding ≥ ${data.contextual_grounding.grounding_threshold}, relevance ≥ ${data.contextual_grounding.relevance_threshold}`
          : 'Off'}
      </Field>
    </dl>
    </>
  );
}

function ProfileCard({ profile }: { profile: GuardrailTemplate }) {
  const [open, setOpen] = useState(false);
  const status = guardrailStatusView(profile.status);
  const detailId = `guardrail-${profile.template_id}`;
  return (
    <li className={`${CARD} p-5`}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <h2 className="text-sm font-semibold text-slate-900">{profile.name}</h2>
            <Badge cls={status.cls} label={status.label} />
          </div>
          {profile.description && <p className="text-sm text-slate-600 mt-1">{profile.description}</p>}
        </div>
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          aria-expanded={open}
          aria-controls={detailId}
          className="text-xs font-medium text-blue-700 hover:underline shrink-0"
        >
          {open ? 'Hide details' : 'Show details'}
        </button>
      </div>
      {open && (
        <div id={detailId} className="mt-4 pt-4 border-t border-slate-200/70">
          <ProfileDetail templateId={profile.template_id} />
        </div>
      )}
    </li>
  );
}

/** Guardrail profiles available to agents. Read-only; profiles are defined as code. */
export default function GuardrailProfiles() {
  const { data, loading, error, reload } = useAsync(() => guardrailsApi.list(), [], 'Failed to load guardrail profiles.');
  if (loading) return <Loading label="Loading guardrail profiles…" />;
  if (error) return <ErrorCard title="Couldn’t load guardrail profiles" message={error} onRetry={reload} />;
  const profiles = (data ?? []).filter((t) => t.status !== 'deleted');
  if (profiles.length === 0) {
    return <EmptyCard title="No guardrail profiles" body="Profiles appear here once the platform baseline has published them." />;
  }
  return (
    <ul className="space-y-3">
      {profiles.map((p) => <ProfileCard key={p.template_id} profile={p} />)}
    </ul>
  );
}
