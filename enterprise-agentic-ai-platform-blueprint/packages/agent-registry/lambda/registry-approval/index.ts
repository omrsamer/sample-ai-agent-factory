/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: MIT-0
 */
import {
  AgentRegistryControlClient,
  GetRegistryCommand,
  GetRegistryRecordCommand,
  ListTagsForResourceCommand,
  SubmitRegistryRecordForApprovalCommand,
  type GetRegistryCommandOutput,
  type GetRegistryRecordCommandOutput,
} from "@aws-sdk/client-agent-registry-control";

export interface ApprovalProperties {
  readonly AccountId: string;
  readonly RegistryId: string;
  readonly RegistryArn: string;
  readonly RecordId: string;
  readonly RecordArn: string;
  readonly RecordName: string;
  readonly RecordVersion: string;
  readonly DescriptorData: string;
  readonly Tags: Readonly<Record<string, string>>;
}

export interface ApprovalEvent {
  readonly RequestType: "Create" | "Update" | "Delete";
  readonly PhysicalResourceId?: string;
  readonly ResourceProperties: ApprovalProperties;
}

export interface RegistryApprovalApi {
  registry(id: string): Promise<GetRegistryCommandOutput>;
  record(
    registryId: string,
    recordId: string,
  ): Promise<GetRegistryRecordCommandOutput>;
  tags(arn: string): Promise<Record<string, string>>;
  submit(registryId: string, recordId: string): Promise<void>;
}

function requireMatch(condition: boolean, message: string): void {
  if (!condition) throw new Error(message);
}

function canonicalTags(tags: Readonly<Record<string, string>>): string {
  return JSON.stringify(
    Object.entries(tags).sort(([a], [b]) => a.localeCompare(b)),
  );
}

function validateRecord(
  record: GetRegistryRecordCommandOutput,
  tags: Readonly<Record<string, string>>,
  expected: ApprovalProperties,
): void {
  requireMatch(
    expected.RegistryArn.split(":")[4] === expected.AccountId &&
      expected.RecordArn.startsWith(`${expected.RegistryArn}/record/`) &&
      record.createdBy === expected.AccountId &&
      record.registryArn === expected.RegistryArn &&
      record.recordArn === expected.RecordArn &&
      record.recordId === expected.RecordId &&
      record.name === expected.RecordName &&
      record.recordType === "CUSTOM" &&
      record.recordVersion === expected.RecordVersion &&
      // GA can omit the optional false flag on control-plane-created records.
      // Exact CFN provenance below remains mandatory, and any detected lineage
      // or malformed flag is refused.
      (record.createdByAutoDetection === false ||
        record.createdByAutoDetection === undefined) &&
      (record.provenance === undefined ||
        (Array.isArray(record.provenance) && record.provenance.length === 0)),
    "Registry record ownership or identity differs from its CloudFormation inventory",
  );
  requireMatch(
    record.descriptors?.custom?.data === expected.DescriptorData,
    "Registry record descriptor differs from its reviewed version",
  );
  requireMatch(
    canonicalTags(tags) === canonicalTags(expected.Tags),
    "Registry record tags differ from its CloudFormation inventory",
  );
}

/** CloudFormation succeeds only after the exact owned record is APPROVED. */
export async function handleApproval(
  event: ApprovalEvent,
  api: RegistryApprovalApi,
  options: { attempts?: number; sleep?: () => Promise<void> } = {},
): Promise<{
  PhysicalResourceId: string;
  Data?: { Status: string; RecordId: string };
}> {
  const expected = event.ResourceProperties;
  const physicalId = event.PhysicalResourceId ?? expected.RecordArn;
  // Retained governance records are never submitted, changed, or deleted here.
  if (event.RequestType === "Delete") return { PhysicalResourceId: physicalId };
  requireMatch(
    /^\d{12}$/.test(expected.AccountId) &&
      expected.RecordId.length > 0 &&
      expected.RecordVersion.length > 0 &&
      expected.Tags["aws:cloudformation:stack-id"]?.length > 0 &&
      expected.Tags["aws:cloudformation:logical-id"]?.length > 0,
    "Approval requires exact account, record version, and CloudFormation provenance",
  );
  const governance = JSON.parse(expected.DescriptorData) as {
    schemaVersion?: string;
    toolId?: string;
    desiredApprovalStatus?: string;
  };
  requireMatch(
    governance.schemaVersion === "agenticai.tool-governance/1.0" &&
      governance.toolId === expected.RecordName &&
      governance.desiredApprovalStatus === "approved",
    "Only the exact reviewed APPROVED catalogue version may be submitted",
  );
  const attempts = options.attempts ?? 12;
  const sleep =
    options.sleep ??
    (() => new Promise<void>((resolve) => setTimeout(resolve, 5000)));
  let submitted = false;
  for (let attempt = 0; attempt < attempts; attempt++) {
    const registry = await api.registry(expected.RegistryId);
    requireMatch(
      registry.registryArn === expected.RegistryArn &&
        registry.registryId === expected.RegistryId &&
        registry.status === "READY" &&
        JSON.stringify(registry.approvalConfiguration?.autoApprovalRules) ===
          JSON.stringify(["APPROVE_ALL"]),
      "Registry identity or automatic approval configuration differs from reviewed source",
    );
    const record = await api.record(expected.RegistryId, expected.RecordId);
    const tags = await api.tags(expected.RecordArn);
    validateRecord(record, tags, expected);
    if (record.status === "APPROVED") {
      return {
        PhysicalResourceId: expected.RecordArn,
        Data: { Status: "APPROVED", RecordId: expected.RecordId },
      };
    }
    requireMatch(
      record.status === "DRAFT",
      "Registry record is not an approvable DRAFT or matching APPROVED record",
    );
    if (!submitted) {
      // These immutable physical identifiers came from the native CFN record.
      await api.submit(expected.RegistryId, expected.RecordId);
      submitted = true;
    }
    if (attempt + 1 < attempts) await sleep();
  }
  throw new Error(
    "Registry record approval was not confirmed within the bounded wait",
  );
}

export async function handler(event: ApprovalEvent): Promise<{
  PhysicalResourceId: string;
  Data?: { Status: string; RecordId: string };
}> {
  if (event.RequestType === "Delete") {
    return {
      PhysicalResourceId:
        event.PhysicalResourceId ?? event.ResourceProperties.RecordArn,
    };
  }
  const client = new AgentRegistryControlClient({
    maxAttempts: 2,
    requestHandler: { connectionTimeout: 2000, requestTimeout: 5000 },
  });
  return handleApproval(event, {
    registry: (registryId) =>
      client.send(new GetRegistryCommand({ registryId })),
    record: (registryId, recordId) =>
      client.send(new GetRegistryRecordCommand({ registryId, recordId })),
    tags: async (resourceArn) =>
      (await client.send(new ListTagsForResourceCommand({ resourceArn })))
        .tags ?? {},
    submit: async (registryId, recordId) => {
      await client.send(
        new SubmitRegistryRecordForApprovalCommand({ registryId, recordId }),
      );
    },
  });
}
