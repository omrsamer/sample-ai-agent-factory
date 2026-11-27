// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

/**
 * Client-side copy of the constraints in the agent governance document schema
 * (`agenticai.agent-governance/1.0`, kept in the agent-registry package). The schema is not
 * imported across the package boundary; `governanceSchema.test.ts` reads the schema file and
 * fails if any enum, pattern, length or required field here drifts from it.
 *
 * Validation here is a convenience. The server validates every write and its answer wins.
 */

export const SCHEMA_VERSION = 'agenticai.agent-governance/1.0';

export const ENVIRONMENTS = ['nonprod', 'prod'] as const;
export const RISK_CLASSES = ['minimal', 'limited', 'high', 'unacceptable'] as const;
export const DATA_CLASSIFICATIONS = ['public', 'internal', 'confidential', 'restricted'] as const;

export const PATTERNS = {
  tenantId: '^[a-z0-9][a-z0-9-]{0,62}$',
  agentId: '^[a-z0-9][a-z0-9-]{0,62}$',
  toolId: '^[a-z0-9][a-z0-9-]{0,62}$',
  runtimeArn: '^arn:aws[a-z-]*:bedrock-agentcore:[a-z0-9-]+:[0-9]{12}:runtime/[A-Za-z0-9_-]+$',
  gatewayArn: '^arn:aws[a-z-]*:bedrock-agentcore:[a-z0-9-]+:[0-9]{12}:gateway/[A-Za-z0-9_-]+$',
  recordVersion: '^[0-9]+\\.[0-9]+\\.[0-9]+$',
} as const;

/** Maximum lengths. A field with `min: 1` may not be empty when it is present. */
export const LENGTHS = {
  applicationId: { min: 1, max: 128 },
  ownerGroup: { min: 1, max: 256 },
  contact: { min: 1, max: 256 },
  businessPurpose: { min: 1, max: 2000 },
  costCentre: { min: 1, max: 128 },
  framework: { min: 0, max: 64 },
  goldenPathName: { min: 1, max: 128 },
  goldenPathVersion: { min: 1, max: 64 },
} as const;

/** Top-level fields the schema requires. */
export const REQUIRED_FIELDS = [
  'schemaVersion',
  'tenantId',
  'agentId',
  'environment',
  'ownerGroup',
  'businessPurpose',
  'riskClass',
  'dataClassification',
  'costCentre',
  'recordVersion',
] as const;

export type Environment = (typeof ENVIRONMENTS)[number];
export type RiskClass = (typeof RISK_CLASSES)[number];
export type DataClassification = (typeof DATA_CLASSIFICATIONS)[number];

/**
 * The governance document as the API returns it: the schema's properties with snake_case keys.
 * Properties this form does not edit (for example the evaluation verdict written by the
 * pipeline) are carried through an update unchanged.
 */
export interface RegistrationDocument {
  schema_version?: string;
  tenant_id?: string;
  agent_id?: string;
  environment?: string;
  owner_group?: string;
  business_purpose?: string;
  risk_class?: string;
  data_classification?: string;
  cost_centre?: string;
  record_version?: string;
  application_id?: string | null;
  contact?: string | null;
  framework?: string | null;
  golden_path?: { name?: string; version?: string } | null;
  runtime_arn?: string | null;
  gateway_arn?: string | null;
  subscribed_tool_ids?: string[] | null;
  [other: string]: unknown;
}

/** Body of create and update: the document without `schema_version`. */
export type RegistrationInput = Omit<RegistrationDocument, 'schema_version'>;

/** The form's state: every input as text, so an empty input is an empty string. */
export interface RegistrationDraft {
  tenantId: string;
  agentId: string;
  environment: string;
  ownerGroup: string;
  contact: string;
  businessPurpose: string;
  riskClass: string;
  dataClassification: string;
  costCentre: string;
  applicationId: string;
  framework: string;
  goldenPathName: string;
  goldenPathVersion: string;
  runtimeArn: string;
  gatewayArn: string;
  subscribedToolIds: string[];
  recordVersion: string;
}

export type DraftField = keyof RegistrationDraft;

export const EMPTY_DRAFT: RegistrationDraft = {
  tenantId: '',
  agentId: '',
  environment: 'nonprod',
  ownerGroup: '',
  contact: '',
  businessPurpose: '',
  riskClass: '',
  dataClassification: '',
  costCentre: '',
  applicationId: '',
  framework: '',
  goldenPathName: '',
  goldenPathVersion: '',
  runtimeArn: '',
  gatewayArn: '',
  subscribedToolIds: [],
  recordVersion: '1.0.0',
};

export const FIELD_LABEL: Record<DraftField, string> = {
  tenantId: 'Tenant',
  agentId: 'Agent id',
  environment: 'Environment',
  ownerGroup: 'Owner group',
  contact: 'Contact',
  businessPurpose: 'Business purpose',
  riskClass: 'Risk class',
  dataClassification: 'Data classification',
  costCentre: 'Cost centre',
  applicationId: 'Application id',
  framework: 'Framework',
  goldenPathName: 'Golden path name',
  goldenPathVersion: 'Golden path version',
  runtimeArn: 'Runtime ARN',
  gatewayArn: 'Tool gateway ARN',
  subscribedToolIds: 'Subscribed tools',
  recordVersion: 'Record version',
};

/**
 * The governed references of a record. Once a record has been submitted these cannot be edited:
 * a different runtime, gateway, tool set, risk class or data classification is a different
 * agent as far as governance is concerned, and needs a new registration.
 */
export const GOVERNED_REFERENCE_FIELDS: readonly DraftField[] = [
  'runtimeArn',
  'gatewayArn',
  'subscribedToolIds',
  'riskClass',
  'dataClassification',
];

/** The identity of a record. It cannot change once the record exists. */
export const IDENTITY_FIELDS: readonly DraftField[] = ['tenantId', 'agentId', 'environment'];

function text(value: unknown): string {
  return typeof value === 'string' ? value : '';
}

/** Form state for a document as the API returned it. Never throws on a malformed document. */
export function draftFromDocument(doc: RegistrationDocument | null | undefined): RegistrationDraft {
  if (!doc) return { ...EMPTY_DRAFT };
  const goldenPath = (doc.golden_path ?? {}) as { name?: unknown; version?: unknown };
  return {
    tenantId: text(doc.tenant_id),
    agentId: text(doc.agent_id),
    environment: text(doc.environment) || EMPTY_DRAFT.environment,
    ownerGroup: text(doc.owner_group),
    contact: text(doc.contact),
    businessPurpose: text(doc.business_purpose),
    riskClass: text(doc.risk_class),
    dataClassification: text(doc.data_classification),
    costCentre: text(doc.cost_centre),
    applicationId: text(doc.application_id),
    framework: text(doc.framework),
    goldenPathName: text(goldenPath.name),
    goldenPathVersion: text(goldenPath.version),
    runtimeArn: text(doc.runtime_arn),
    gatewayArn: text(doc.gateway_arn),
    subscribedToolIds: Array.isArray(doc.subscribed_tool_ids)
      ? doc.subscribed_tool_ids.filter((t): t is string => typeof t === 'string')
      : [],
    recordVersion: text(doc.record_version) || EMPTY_DRAFT.recordVersion,
  };
}

/** Keys of the request body this form owns. Everything else in `base` is carried through. */
const EDITED_KEYS = [
  'schema_version', 'tenant_id', 'agent_id', 'environment', 'owner_group', 'business_purpose', 'risk_class',
  'data_classification', 'cost_centre', 'record_version', 'application_id', 'contact', 'framework', 'golden_path',
  'runtime_arn', 'gateway_arn', 'subscribed_tool_ids',
];

/** Compares two `major.minor.patch` versions. Negative, zero or positive, like a sort comparator. */
export function compareVersions(a: string, b: string): number {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) - (pb[i] ?? 0);
  }
  return 0;
}

/**
 * Builds the request body. Optional fields left empty are omitted rather than sent as empty
 * strings, and properties of `base` this form does not edit are carried through.
 *
 * `currentVersion` is the record's version when editing. The version is sent only when the
 * user raised it; otherwise it is omitted and the server raises the patch number itself.
 */
export function inputFromDraft(
  draft: RegistrationDraft,
  base?: RegistrationDocument | null,
  currentVersion?: string | null,
): RegistrationInput {
  const carried: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(base ?? {})) {
    if (!EDITED_KEYS.includes(key) && value !== null && value !== undefined) carried[key] = value;
  }
  const t = (v: string) => v.trim();
  const input: RegistrationInput = {
    ...carried,
    tenant_id: t(draft.tenantId),
    agent_id: t(draft.agentId),
    environment: draft.environment,
    owner_group: t(draft.ownerGroup),
    business_purpose: t(draft.businessPurpose),
    risk_class: draft.riskClass,
    data_classification: draft.dataClassification,
    cost_centre: t(draft.costCentre),
  };
  const version = t(draft.recordVersion);
  if (version && version !== (currentVersion ?? '')) input.record_version = version;
  if (t(draft.applicationId)) input.application_id = t(draft.applicationId);
  if (t(draft.contact)) input.contact = t(draft.contact);
  if (t(draft.framework)) input.framework = t(draft.framework);
  if (t(draft.goldenPathName) || t(draft.goldenPathVersion)) {
    input.golden_path = { name: t(draft.goldenPathName), version: t(draft.goldenPathVersion) };
  }
  if (t(draft.runtimeArn)) input.runtime_arn = t(draft.runtimeArn);
  if (t(draft.gatewayArn)) input.gateway_arn = t(draft.gatewayArn);
  if (draft.subscribedToolIds.length > 0) input.subscribed_tool_ids = [...new Set(draft.subscribedToolIds)].sort();
  return input;
}

export type FieldErrors = Partial<Record<DraftField, string>>;

function matches(pattern: string, value: string): boolean {
  return new RegExp(pattern).test(value);
}

const ID_HINT = 'Use lower-case letters, digits and hyphens, starting with a letter or digit (63 characters at most).';

/**
 * Validates the form against the copied schema constraints. An empty result means valid.
 * `currentVersion` is the record's version when editing: a changed version must be higher.
 */
export function validateDraft(draft: RegistrationDraft, currentVersion?: string | null): FieldErrors {
  const errors: FieldErrors = {};
  const value = (field: Exclude<DraftField, 'subscribedToolIds'>) => draft[field].trim();

  const requireText = (field: 'ownerGroup' | 'businessPurpose' | 'costCentre', max: number) => {
    const v = value(field);
    if (!v) errors[field] = `${FIELD_LABEL[field]} is required.`;
    else if (v.length > max) errors[field] = `${FIELD_LABEL[field]} must be ${max} characters or fewer.`;
  };
  const optionalText = (field: 'applicationId' | 'contact' | 'framework', max: number) => {
    if (value(field).length > max) errors[field] = `${FIELD_LABEL[field]} must be ${max} characters or fewer.`;
  };

  for (const field of ['tenantId', 'agentId'] as const) {
    const v = value(field);
    if (!v) errors[field] = `${FIELD_LABEL[field]} is required.`;
    else if (!matches(PATTERNS[field], v)) errors[field] = ID_HINT;
  }
  if (!(ENVIRONMENTS as readonly string[]).includes(draft.environment)) errors.environment = 'Choose an environment.';
  if (!(RISK_CLASSES as readonly string[]).includes(draft.riskClass)) errors.riskClass = 'Choose a risk class.';
  if (!(DATA_CLASSIFICATIONS as readonly string[]).includes(draft.dataClassification)) {
    errors.dataClassification = 'Choose a data classification.';
  }
  requireText('ownerGroup', LENGTHS.ownerGroup.max);
  requireText('businessPurpose', LENGTHS.businessPurpose.max);
  requireText('costCentre', LENGTHS.costCentre.max);
  optionalText('applicationId', LENGTHS.applicationId.max);
  optionalText('contact', LENGTHS.contact.max);
  optionalText('framework', LENGTHS.framework.max);

  const name = value('goldenPathName');
  const version = value('goldenPathVersion');
  if (name || version) {
    if (!name) errors.goldenPathName = 'Give the golden path name, or clear the version.';
    else if (name.length > LENGTHS.goldenPathName.max) {
      errors.goldenPathName = `Golden path name must be ${LENGTHS.goldenPathName.max} characters or fewer.`;
    }
    if (!version) errors.goldenPathVersion = 'Give the golden path version, or clear the name.';
    else if (version.length > LENGTHS.goldenPathVersion.max) {
      errors.goldenPathVersion = `Golden path version must be ${LENGTHS.goldenPathVersion.max} characters or fewer.`;
    }
  }

  const runtimeArn = value('runtimeArn');
  if (runtimeArn && !matches(PATTERNS.runtimeArn, runtimeArn)) {
    errors.runtimeArn = 'Enter the ARN of an Amazon Bedrock AgentCore runtime (it ends in runtime/<id>).';
  }
  const gatewayArn = value('gatewayArn');
  if (gatewayArn && !matches(PATTERNS.gatewayArn, gatewayArn)) {
    errors.gatewayArn = 'Enter the ARN of an Amazon Bedrock AgentCore gateway (it ends in gateway/<id>).';
  }
  if (draft.subscribedToolIds.some((id) => !matches(PATTERNS.toolId, id))) {
    errors.subscribedToolIds = 'One of the selected tool ids is not a valid tool id.';
  }
  const recordVersion = value('recordVersion');
  if (recordVersion && !matches(PATTERNS.recordVersion, recordVersion)) {
    errors.recordVersion = 'Use three numbers separated by dots, for example 1.0.0.';
  } else if (recordVersion && currentVersion && recordVersion !== currentVersion && compareVersions(recordVersion, currentVersion) <= 0) {
    errors.recordVersion = `Enter a version higher than ${currentVersion}, or leave it as it is.`;
  }

  return errors;
}

const SERVER_NAME_TO_FIELD: Record<string, DraftField> = (() => {
  const map: Record<string, DraftField> = {};
  for (const field of Object.keys(FIELD_LABEL) as DraftField[]) {
    map[field] = field;
    map[field.replace(/[A-Z]/g, (c) => `_${c.toLowerCase()}`)] = field;
  }
  return map;
})();

/**
 * Maps where the server says an error is to the form field that owns it. The server names a
 * field either by request key (`risk_class`) or by stored key (`riskClass`), with or without
 * a `body` or `document` prefix.
 */
export function fieldForDocumentPath(path: readonly (string | number)[]): DraftField | null {
  const parts = path.filter((p) => p !== 'body' && p !== 'document').map(String);
  if (parts.length === 0) return null;
  if (parts[0] === 'goldenPath' || parts[0] === 'golden_path') {
    return parts[1] === 'version' ? 'goldenPathVersion' : 'goldenPathName';
  }
  const [first] = parts;
  return Object.prototype.hasOwnProperty.call(SERVER_NAME_TO_FIELD, first) ? SERVER_NAME_TO_FIELD[first] : null;
}

/** The field a plain validation message such as `document.riskClass must be …` is about. */
export function fieldForMessage(message: string): DraftField | null {
  const match = /^(?:document\.)?([A-Za-z_]+(?:\.[A-Za-z_]+)?)\b/.exec(message.trim());
  return match ? fieldForDocumentPath(match[1].split('.')) : null;
}

export interface DiffRow {
  field: DraftField;
  label: string;
  before: string;
  after: string;
}

function shown(draft: RegistrationDraft, field: DraftField): string {
  const v = draft[field];
  return Array.isArray(v) ? [...v].sort().join(', ') : v.trim();
}

/**
 * The fields that differ between two documents, in form order. Empty when nothing changed.
 * The record version is left out: the server raises it on every update, so it always differs
 * and says nothing about what was changed.
 */
export function documentDiff(
  previous: RegistrationDocument | null | undefined,
  next: RegistrationDocument | null | undefined,
): DiffRow[] {
  if (!previous || !next) return [];
  const before = draftFromDocument(previous);
  const after = draftFromDocument(next);
  return (Object.keys(FIELD_LABEL) as DraftField[])
    .filter((field) => field !== 'recordVersion' && shown(before, field) !== shown(after, field))
    .map((field) => ({ field, label: FIELD_LABEL[field], before: shown(before, field), after: shown(after, field) }));
}
