// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describe, expect, it } from 'vitest';
import appSrc from '../../App.tsx?raw';
import profilesSrc from './GuardrailProfiles.tsx?raw';
import { CATALOG_SECTIONS, resolveCatalogSection } from './catalogSections';
import { guardrailFeatures, guardrailStatusView } from './guardrailSummary';

describe('governance catalog sections', () => {
  it('lists Agents, Tools, Guardrail profiles and Models', () => {
    expect(CATALOG_SECTIONS.map((s) => s.label)).toEqual(['Agents', 'Tools', 'Guardrail profiles', 'Models']);
  });

  it('resolves a section id and rejects anything else', () => {
    expect(resolveCatalogSection('models')?.label).toBe('Models');
    expect(resolveCatalogSection('prompts')).toBeNull();
    expect(resolveCatalogSection(undefined)).toBeNull();
  });

  it('is routed by section, with a default', () => {
    expect(appSrc).toContain('path="/catalog/:section"');
    expect(appSrc).toContain('<Navigate to="/catalog/agents" replace />');
  });
});

describe('guardrail profiles', () => {
  it('summarises the protections a profile configures', () => {
    expect(
      guardrailFeatures({
        content_filters: [{ type: 'HATE', input_strength: 'HIGH', output_strength: 'HIGH' }],
        pii_entities: [],
        sensitive_regexes: [{ name: 'internal id', pattern: 'ID-[0-9]+', action: 'ANONYMIZE' }],
        denied_topics: [{ name: 'Legal advice', definition: 'Advice on legal matters', examples: [] }],
        word_filter: { enable_profanity: false, blocked_words: ['example'] },
        contextual_grounding: { enabled: true, grounding_threshold: 0.7, relevance_threshold: 0.7 },
      }),
    ).toEqual(['Content filters', 'Sensitive information', 'Denied topics', 'Word filters', 'Contextual grounding']);
    expect(guardrailFeatures({})).toEqual([]);
  });

  it('labels a status and shows an unknown one as recorded', () => {
    expect(guardrailStatusView('active').label).toBe('Active');
    expect(guardrailStatusView('archived').label).toBe('archived');
    expect(guardrailStatusView('').label).toBe('Unknown');
  });

  it('offers no create, edit, publish or delete control', () => {
    expect(profilesSrc).not.toMatch(/Create|Delete|Publish|<input|<form/);
  });
});
