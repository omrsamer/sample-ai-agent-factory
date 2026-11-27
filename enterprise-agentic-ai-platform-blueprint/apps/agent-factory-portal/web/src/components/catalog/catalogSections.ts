// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

/** Sections of the governance catalog. One list for the page, its routes and its test. */
export interface CatalogSection {
  id: 'agents' | 'tools' | 'guardrails' | 'models';
  label: string;
  blurb: string;
}

export const CATALOG_SECTIONS: CatalogSection[] = [
  { id: 'agents', label: 'Agents', blurb: 'Agent records in the registry, with owner and lifecycle state.' },
  { id: 'tools', label: 'Tools', blurb: 'Tool records in the registry, with owner, cost centre and the target each one invokes.' },
  { id: 'guardrails', label: 'Guardrail profiles', blurb: 'The guardrail configurations agents may attach.' },
  { id: 'models', label: 'Models', blurb: 'The foundation models approved for use, and the Regions each is available in.' },
];

export function resolveCatalogSection(id: string | undefined): CatalogSection | null {
  return CATALOG_SECTIONS.find((s) => s.id === id) ?? null;
}
