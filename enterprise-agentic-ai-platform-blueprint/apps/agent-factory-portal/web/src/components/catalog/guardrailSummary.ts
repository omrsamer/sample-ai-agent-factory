// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import type { GuardrailStatus, GuardrailTemplate } from '../../types';

const STATUS_VIEW: Record<GuardrailStatus, { cls: string; label: string }> = {
  draft: { cls: 'bg-slate-100 text-slate-700', label: 'Draft' },
  creating: { cls: 'bg-blue-50 text-blue-700', label: 'Creating' },
  active: { cls: 'bg-emerald-50 text-emerald-700', label: 'Active' },
  updating: { cls: 'bg-amber-50 text-amber-700', label: 'Updating' },
  failed: { cls: 'bg-red-50 text-red-700', label: 'Failed' },
  deleting: { cls: 'bg-orange-50 text-orange-700', label: 'Deleting' },
  deleted: { cls: 'bg-slate-50 text-slate-500', label: 'Deleted' },
};

export function guardrailStatusView(status: string): { cls: string; label: string } {
  return Object.prototype.hasOwnProperty.call(STATUS_VIEW, status)
    ? STATUS_VIEW[status as GuardrailStatus]
    : { cls: 'bg-slate-100 text-slate-600', label: status || 'Unknown' };
}

/** The protections a profile configures, as short labels. */
export function guardrailFeatures(t: Partial<GuardrailTemplate>): string[] {
  const features: string[] = [];
  if ((t.content_filters?.length ?? 0) > 0) features.push('Content filters');
  if ((t.pii_entities?.length ?? 0) > 0 || (t.sensitive_regexes?.length ?? 0) > 0) features.push('Sensitive information');
  if ((t.denied_topics?.length ?? 0) > 0) features.push('Denied topics');
  if (t.word_filter?.enable_profanity || (t.word_filter?.blocked_words?.length ?? 0) > 0) features.push('Word filters');
  if (t.contextual_grounding?.enabled) features.push('Contextual grounding');
  return features;
}
