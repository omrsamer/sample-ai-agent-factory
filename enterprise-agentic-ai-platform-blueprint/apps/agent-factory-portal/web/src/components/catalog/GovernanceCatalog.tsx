// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { Navigate, useNavigate, useParams } from 'react-router-dom';
import { AgentsTable } from '../governance/AgentsList';
import { Page, PageHeader, TabBar } from '../shared/ui';
import { CatalogModels, CatalogTools } from './CatalogTables';
import { CATALOG_SECTIONS, resolveCatalogSection } from './catalogSections';
import GuardrailProfiles from './GuardrailProfiles';

/**
 * Governance catalog: what the platform has approved for teams to build with. Read-only;
 * entries are published through code and pipelines.
 */
export default function GovernanceCatalog() {
  const { section: sectionId } = useParams();
  const navigate = useNavigate();
  const section = resolveCatalogSection(sectionId);
  if (!section) return <Navigate to="/catalog/agents" replace />;

  return (
    <Page>
      <PageHeader
        title="Governance catalog"
        subtitle="What the platform has approved for teams to build with. Entries are published through code and pipelines, not from this portal."
      />
      <TabBar
        tabs={CATALOG_SECTIONS}
        active={section.id}
        label="Catalog sections"
        onSelect={(id) => navigate(`/catalog/${id}`)}
      />
      <p className="text-sm text-slate-600 mb-4">{section.blurb}</p>
      {section.id === 'agents' ? (
        <AgentsTable />
      ) : section.id === 'tools' ? (
        <CatalogTools />
      ) : section.id === 'guardrails' ? (
        <GuardrailProfiles />
      ) : (
        <CatalogModels />
      )}
    </Page>
  );
}
