// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { useId, useRef, useState, type FormEvent, type ReactNode } from 'react';
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { agentsApi, catalogApi } from '../api/client';
import type { Agent, UserTenant } from '../api/client';
import { useUser } from '../contexts/UserContext';
import { CARD, ErrorCard, Loading, Page, PageHeader } from '../components/shared/ui';
import { useAsync } from '../components/shared/useAsync';
import ActionFailurePanel from './ActionFailurePanel';
import {
  DATA_CLASSIFICATIONS,
  EMPTY_DRAFT,
  ENVIRONMENTS,
  FIELD_LABEL,
  GOVERNED_REFERENCE_FIELDS,
  IDENTITY_FIELDS,
  LENGTHS,
  PATTERNS,
  REVIEW_BY_MAX_DAYS,
  RISK_CLASSES,
  draftFromDocument,
  inputFromDraft,
  latestReviewBy,
  validateDraft,
  type DraftField,
  type FieldErrors,
  type RegistrationDraft,
} from './governanceSchema';
import { classifyFailure, registrationsApi, type ActionFailure, type RegistrationDetail } from './registrationsClient';
import {
  AUDIT_INCOMPLETE_NOTE,
  GOVERNED_REFERENCES_NOTE,
  PIPELINE_NOTE,
  RETURNS_TO_DRAFT_NOTE,
  authoritiesOf,
  offeredActions,
} from './registrationView';

const INPUT = 'mt-1 w-full px-3 py-2 text-sm rounded-lg border border-slate-400 bg-white disabled:bg-slate-100 disabled:text-slate-600';
const PRIMARY = 'px-3.5 py-1.5 rounded-lg bg-blue-700 text-white text-sm font-medium hover:bg-blue-800 disabled:opacity-50';
const SECONDARY = 'px-3.5 py-1.5 rounded-lg bg-white border border-slate-300 text-slate-700 text-sm font-medium hover:bg-slate-50';

/** What is known about a discovered agent, as the starting point of its registration. */
export function draftFromAgent(agent: Agent): RegistrationDraft {
  const idCandidate = (agent.name ?? '').trim();
  const environments = Object.keys(agent.agent_arns ?? {});
  return {
    ...EMPTY_DRAFT,
    tenantId: agent.tenant_id ?? '',
    agentId: new RegExp(PATTERNS.agentId).test(idCandidate) ? idCandidate : '',
    environment:
      environments.length === 1 && (ENVIRONMENTS as readonly string[]).includes(environments[0])
        ? environments[0]
        : EMPTY_DRAFT.environment,
    businessPurpose: agent.purpose ?? '',
    framework: agent.framework ?? '',
    runtimeArn: agent.agent_arn ?? '',
  };
}

function FieldShell({
  field,
  errors,
  required,
  hint,
  locked,
  children,
}: {
  field: DraftField;
  errors: FieldErrors;
  required?: boolean;
  hint?: string;
  /** Why the field cannot be edited, or null when it can. */
  locked?: string | null;
  children: (ids: { id: string; describedBy: string | undefined; invalid: boolean }) => ReactNode;
}) {
  const id = useId();
  const error = errors[field];
  const describedBy = [hint || locked ? `${id}-hint` : null, error ? `${id}-error` : null].filter(Boolean).join(' ') || undefined;
  return (
    <div>
      <label htmlFor={id} className="block text-sm font-medium text-slate-800">
        {FIELD_LABEL[field]}
        {required && <span className="text-slate-600 font-normal"> (required)</span>}
      </label>
      {children({ id, describedBy, invalid: !!error })}
      {(hint || locked) && (
        <p id={`${id}-hint`} className="text-xs text-slate-600 mt-1">
          {locked ?? hint}
        </p>
      )}
      {error && (
        <p id={`${id}-error`} className="text-xs text-red-700 mt-1">
          {error}
        </p>
      )}
    </div>
  );
}

/**
 * Create or edit a registration. Saving stores a draft; submitting for approval is a separate
 * action on the record's page.
 */
export default function RegistrationForm() {
  const { id: recordId } = useParams();
  const [searchParams] = useSearchParams();
  const fromAgentId = recordId ? null : searchParams.get('from');
  const { user, isLoading: userLoading } = useUser();
  const who = authoritiesOf(user);

  const existing = useAsync<RegistrationDetail | null>(
    () => (recordId ? registrationsApi.get(recordId) : Promise.resolve(null)),
    [recordId],
    'Failed to load the registration.',
  );
  const source = useAsync<Agent | null>(
    () => (fromAgentId ? agentsApi.get(fromAgentId) : Promise.resolve(null)),
    [fromAgentId],
    'Failed to load the agent.',
  );

  const backTo = recordId ? `/registrations/${encodeURIComponent(recordId)}` : '/registrations';

  if (!userLoading && !who.registrar) {
    return (
      <Page wide={false}>
        <PageHeader title="Register agent" />
        <ErrorCard title="You do not hold the authority for this action" message="Registering or editing a record needs the registrar authority." />
      </Page>
    );
  }
  if (existing.error) {
    return (
      <Page wide={false}>
        <PageHeader title="Edit registration" />
        <ErrorCard title="Couldn’t load the registration" message={existing.error} onRetry={existing.reload} />
      </Page>
    );
  }
  if (userLoading || existing.loading || source.loading) {
    return (
      <Page wide={false}>
        <Loading label="Loading…" />
      </Page>
    );
  }

  const record = existing.data;
  const initial = record
    ? draftFromDocument(record.document)
    : source.data
      ? draftFromAgent(source.data)
      : { ...EMPTY_DRAFT, tenantId: who.tenants?.length === 1 ? who.tenants[0] : '' };

  return (
    <RegistrationEditor
      key={recordId ?? `new:${fromAgentId ?? ''}`}
      recordId={recordId}
      record={record}
      initial={initial}
      backTo={backTo}
      tenantChoices={who.tenants}
      tenantNames={user?.tenants ?? []}
      locks={record ? offeredActions(record, who).editLocksGovernedReferences : false}
      returnsToDraft={record ? offeredActions(record, who).editReturnsToDraft : false}
      sourceFailed={!!source.error}
      onRefresh={existing.reload}
    />
  );
}

function RegistrationEditor({
  recordId,
  record,
  initial,
  backTo,
  tenantChoices,
  tenantNames,
  locks,
  returnsToDraft,
  sourceFailed,
  onRefresh,
}: {
  recordId: string | undefined;
  record: RegistrationDetail | null;
  initial: RegistrationDraft;
  backTo: string;
  /** The tenants the caller acts for, or null when any tenant may be entered. */
  tenantChoices: string[] | null;
  tenantNames: UserTenant[];
  locks: boolean;
  returnsToDraft: boolean;
  sourceFailed: boolean;
  onRefresh: () => void;
}) {
  const navigate = useNavigate();
  const tools = useAsync(() => catalogApi.tools(), [], 'Failed to load the tools catalog.');
  const [draft, setDraft] = useState<RegistrationDraft>(initial);
  // The latest review date the API accepts, counted from the day the form was opened.
  const [latestReview] = useState(() => latestReviewBy(new Date()));
  const [errors, setErrors] = useState<FieldErrors>({});
  const [failure, setFailure] = useState<ActionFailure | null>(null);
  const [saving, setSaving] = useState(false);
  const summaryRef = useRef<HTMLDivElement>(null);
  const [auditGap, setAuditGap] = useState<string | null>(null);
  const currentVersion = record?.record_version ?? null;
  const lockReason = (field: DraftField): string | null => {
    if (record && IDENTITY_FIELDS.includes(field)) return 'Cannot be changed once the record exists.';
    if (locks && GOVERNED_REFERENCE_FIELDS.includes(field)) return 'Cannot be changed on an approved record.';
    return null;
  };
  const isLocked = (field: DraftField) => lockReason(field) !== null;

  const set = <K extends DraftField>(field: K, value: RegistrationDraft[K]) => {
    setDraft((d) => ({ ...d, [field]: value }));
    setErrors((e) => {
      if (!e[field]) return e;
      const next = { ...e };
      delete next[field];
      return next;
    });
  };

  const onSubmit = async (event: FormEvent) => {
    event.preventDefault();
    setFailure(null);
    const found = validateDraft(draft, currentVersion, new Date());
    setErrors(found);
    if (Object.keys(found).length > 0) {
      summaryRef.current?.focus();
      return;
    }
    setSaving(true);
    try {
      const input = inputFromDraft(draft, record?.document, currentVersion);
      const result = recordId ? await registrationsApi.update(recordId, input) : await registrationsApi.create(input);
      const savedId = result.registration?.record_id ?? recordId;
      if (result.audit_complete === false) {
        // Stay here so the reference can be read; the record itself was saved.
        setAuditGap(result.request_id);
        summaryRef.current?.focus();
      } else if (savedId) {
        navigate(`/registrations/${encodeURIComponent(savedId)}`);
      } else {
        navigate('/registrations');
      }
    } catch (err) {
      const classified = classifyFailure(err, 'The registration could not be saved');
      setFailure(classified);
      setErrors(classified.fieldErrors);
      summaryRef.current?.focus();
    } finally {
      setSaving(false);
    }
  };

  const text = (field: Exclude<DraftField, 'subscribedToolIds'>, opts: { required?: boolean; hint?: string; maxLength?: number; multiline?: boolean } = {}) => (
    <FieldShell field={field} errors={errors} required={opts.required} hint={opts.hint} locked={lockReason(field)}>
      {({ id, describedBy, invalid }) =>
        opts.multiline ? (
          <textarea
            id={id}
            rows={4}
            className={INPUT}
            value={draft[field]}
            maxLength={opts.maxLength}
            aria-required={opts.required || undefined}
            aria-invalid={invalid || undefined}
            aria-describedby={describedBy}
            onChange={(e) => set(field, e.target.value)}
          />
        ) : (
          <input
            id={id}
            type="text"
            className={INPUT}
            value={draft[field]}
            maxLength={opts.maxLength}
            disabled={isLocked(field)}
            autoComplete="off"
            spellCheck={false}
            aria-required={opts.required || undefined}
            aria-invalid={invalid || undefined}
            aria-describedby={describedBy}
            onChange={(e) => set(field, e.target.value)}
          />
        )
      }
    </FieldShell>
  );

  const choice = (field: 'environment' | 'riskClass' | 'dataClassification', options: readonly string[]) => (
    <FieldShell field={field} errors={errors} required locked={lockReason(field)}>
      {({ id, describedBy, invalid }) => (
        <select
          id={id}
          className={INPUT}
          value={draft[field]}
          disabled={isLocked(field)}
          aria-required
          aria-invalid={invalid || undefined}
          aria-describedby={describedBy}
          onChange={(e) => set(field, e.target.value)}
        >
          {field !== 'environment' && <option value="">Choose…</option>}
          {options.map((o) => (
            <option key={o} value={o}>{o}</option>
          ))}
        </select>
      )}
    </FieldShell>
  );

  const toolIds = [...new Set([...(tools.data ?? []).map((t) => t.tool_id), ...draft.subscribedToolIds])].sort();
  const toolName = new Map((tools.data ?? []).map((t) => [t.tool_id, t.name]));
  const errorCount = Object.keys(errors).length;

  return (
    <Page wide={false}>
      <Link to={backTo} className="text-xs text-slate-600 hover:text-slate-800">← Back</Link>
      <PageHeader title={recordId ? 'Edit registration' : 'Register agent'} subtitle={PIPELINE_NOTE} />

      <div ref={summaryRef} tabIndex={-1} className="space-y-3 mb-4 outline-none">
        <ActionFailurePanel failure={failure} onRefresh={onRefresh} />
        {errorCount > 0 && !failure && (
          <div className="rounded-xl border border-red-200 bg-red-50 p-4" role="alert">
            <p className="text-sm font-semibold text-red-800">
              {errorCount === 1 ? '1 field needs attention.' : `${errorCount} fields need attention.`}
            </p>
          </div>
        )}
        {sourceFailed && <p className="text-sm text-slate-600">The agent’s details could not be loaded, so the form starts empty.</p>}
        {auditGap && (
          <p className="text-sm text-amber-900 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2" role="alert">
            {AUDIT_INCOMPLETE_NOTE} Reference: <span className="font-mono break-all">{auditGap}</span>{' '}
            <Link to={backTo}>Back to the record</Link>
          </p>
        )}
        {returnsToDraft && <p className="text-sm text-amber-900 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2">{RETURNS_TO_DRAFT_NOTE}</p>}
        {locks && <p className="text-sm text-slate-700 bg-slate-100 rounded-lg px-3 py-2">{GOVERNED_REFERENCES_NOTE}</p>}
      </div>

      <form onSubmit={onSubmit} noValidate className="space-y-5">
        <fieldset className={`${CARD} p-5`}>
          <legend className="text-sm font-semibold text-slate-900 px-1">Identity</legend>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {tenantChoices && !record ? (
              <FieldShell field="tenantId" errors={errors} required>
                {({ id, describedBy, invalid }) => (
                  <select
                    id={id}
                    className={INPUT}
                    value={draft.tenantId}
                    aria-required
                    aria-invalid={invalid || undefined}
                    aria-describedby={describedBy}
                    onChange={(e) => set('tenantId', e.target.value)}
                  >
                    <option value="">Choose…</option>
                    {[...new Set([...tenantChoices, ...(draft.tenantId ? [draft.tenantId] : [])])].map((tid) => (
                      <option key={tid} value={tid}>{tenantNames.find((t) => t.id === tid)?.name ?? tid}</option>
                    ))}
                  </select>
                )}
              </FieldShell>
            ) : (
              text('tenantId', { required: true, hint: 'Lower-case letters, digits and hyphens.' })
            )}
            {text('agentId', { required: true, hint: 'Lower-case letters, digits and hyphens.' })}
            {choice('environment', ENVIRONMENTS)}
            {text('applicationId', { maxLength: LENGTHS.applicationId.max })}
          </div>
        </fieldset>

        <fieldset className={`${CARD} p-5`}>
          <legend className="text-sm font-semibold text-slate-900 px-1">Ownership and purpose</legend>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {text('ownerGroup', { required: true, maxLength: LENGTHS.ownerGroup.max, hint: 'The team that owns and operates the agent. It is the agent’s accountable owner.' })}
            {text('sponsor', { maxLength: LENGTHS.sponsor.max, hint: 'The accountable person, by name or email. Optional.' })}
            <FieldShell field="reviewBy" errors={errors} hint={`The date by which this registration must be reviewed again, at most ${REVIEW_BY_MAX_DAYS} days ahead.`}>
              {({ id, describedBy, invalid }) => (
                <input
                  id={id}
                  type="date"
                  className={INPUT}
                  max={latestReview}
                  value={draft.reviewBy}
                  aria-invalid={invalid || undefined}
                  aria-describedby={describedBy}
                  onChange={(e) => set('reviewBy', e.target.value)}
                />
              )}
            </FieldShell>
            {text('contact', { maxLength: LENGTHS.contact.max, hint: 'A team mailbox or channel, not a personal address.' })}
            {text('costCentre', { required: true, maxLength: LENGTHS.costCentre.max })}
            <div className="sm:col-span-2">
              {text('businessPurpose', { required: true, maxLength: LENGTHS.businessPurpose.max, multiline: true })}
            </div>
          </div>
        </fieldset>

        <fieldset className={`${CARD} p-5`}>
          <legend className="text-sm font-semibold text-slate-900 px-1">Classification</legend>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {choice('riskClass', RISK_CLASSES)}
            {choice('dataClassification', DATA_CLASSIFICATIONS)}
          </div>
        </fieldset>

        <fieldset className={`${CARD} p-5`}>
          <legend className="text-sm font-semibold text-slate-900 px-1">Build and runtime</legend>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {text('framework', { maxLength: LENGTHS.framework.max })}
            {text('recordVersion', {
              hint: record
                ? 'Leave it as it is and the server raises the last number, or enter a higher version.'
                : 'Three numbers separated by dots. Leave empty for 1.0.0.',
            })}
            {text('goldenPathName', { maxLength: LENGTHS.goldenPathName.max })}
            {text('goldenPathVersion', { maxLength: LENGTHS.goldenPathVersion.max })}
            <div className="sm:col-span-2">{text('runtimeArn', { hint: 'The runtime the Workload pipeline deployed.' })}</div>
            <div className="sm:col-span-2">{text('gatewayArn', { hint: 'The tool gateway the agent calls through.' })}</div>
          </div>
        </fieldset>

        <fieldset className={`${CARD} p-5`} disabled={isLocked('subscribedToolIds')}>
          <legend className="text-sm font-semibold text-slate-900 px-1">{FIELD_LABEL.subscribedToolIds}</legend>
          {isLocked('subscribedToolIds') && <p className="text-xs text-slate-600 mb-2">{lockReason('subscribedToolIds')}</p>}
          {tools.loading ? (
            <Loading label="Loading the tools catalog…" />
          ) : toolIds.length === 0 ? (
            <p className="text-sm text-slate-600">
              {tools.error ? `The tools catalog could not be loaded. ${tools.error}` : 'The tools catalog is empty.'}
            </p>
          ) : (
            <ul className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-1.5">
              {toolIds.map((toolId) => (
                <li key={toolId}>
                  <label className="flex items-start gap-2 text-sm text-slate-800">
                    <input
                      type="checkbox"
                      className="mt-0.5"
                      checked={draft.subscribedToolIds.includes(toolId)}
                      onChange={(e) =>
                        set(
                          'subscribedToolIds',
                          e.target.checked ? [...draft.subscribedToolIds, toolId] : draft.subscribedToolIds.filter((t) => t !== toolId),
                        )
                      }
                    />
                    <span className="min-w-0 break-words">
                      {toolName.get(toolId) ?? toolId}
                      {toolName.has(toolId) && <span className="block text-xs text-slate-600 font-mono break-all">{toolId}</span>}
                    </span>
                  </label>
                </li>
              ))}
            </ul>
          )}
          {errors.subscribedToolIds && <p className="text-xs text-red-700 mt-2">{errors.subscribedToolIds}</p>}
        </fieldset>

        <div className="flex items-center gap-2">
          <button type="submit" className={PRIMARY} disabled={saving}>
            {saving ? 'Saving…' : recordId ? 'Save changes' : 'Save draft'}
          </button>
          <Link to={backTo} className={SECONDARY}>Cancel</Link>
          {!recordId && <span className="text-xs text-slate-600">Saving does not submit the record for approval.</span>}
        </div>
      </form>
    </Page>
  );
}
