import {
  handleApproval,
  type ApprovalEvent,
  type ApprovalProperties,
  type RegistryApprovalApi,
} from "./index";
import type { GetRegistryRecordCommandOutput } from "@aws-sdk/client-agent-registry-control";

const registryArn =
  "arn:aws:agent-registry:eu-west-1:123456789012:registry/abcdefgh1234";
const expected: ApprovalProperties = {
  AccountId: "123456789012",
  RegistryId: "abcdefgh1234",
  RegistryArn: registryArn,
  RecordId: "record1234567",
  RecordArn: `${registryArn}/record/record1234567`,
  RecordName: "tool-echo",
  RecordVersion: "2.0.0",
  DescriptorData: JSON.stringify({
    schemaVersion: "agenticai.tool-governance/1.0",
    toolId: "tool-echo",
    desiredApprovalStatus: "approved",
  }),
  Tags: {
    environment: "nonprod",
    "aws:cloudformation:stack-id":
      "arn:aws:cloudformation:eu-west-1:123456789012:stack/Registry/owned",
    "aws:cloudformation:stack-name": "Registry",
    "aws:cloudformation:logical-id": "RecordToolEcho",
  },
};
const event: ApprovalEvent = {
  RequestType: "Create",
  ResourceProperties: expected,
};
const draft = {
  $metadata: {},
  registryArn,
  recordArn: expected.RecordArn,
  recordId: expected.RecordId,
  name: expected.RecordName,
  recordType: "CUSTOM" as const,
  recordVersion: expected.RecordVersion,
  createdBy: expected.AccountId,
  createdByAutoDetection: false,
  descriptors: { custom: { data: expected.DescriptorData } },
  status: "DRAFT" as const,
  createdAt: new Date("2026-01-01T00:00:00Z"),
  updatedAt: new Date("2026-01-01T00:00:00Z"),
};
const approved = { ...draft, status: "APPROVED" as const };

function fixture(
  records: GetRegistryRecordCommandOutput[] = [draft, approved],
) {
  const reads = [...records];
  const api: RegistryApprovalApi = {
    registry: jest.fn().mockResolvedValue({
      $metadata: {},
      registryArn,
      registryId: expected.RegistryId,
      status: "READY",
      approvalConfiguration: { autoApprovalRules: ["APPROVE_ALL"] },
    }),
    record: jest
      .fn()
      .mockImplementation(async () =>
        reads.length > 1 ? reads.shift() : reads[0],
      ),
    tags: jest.fn().mockResolvedValue({ ...expected.Tags }),
    submit: jest.fn().mockResolvedValue(undefined),
  };
  return api;
}

test("native creation's DRAFT is submitted and deployment waits for actual APPROVED", async () => {
  const api = fixture();
  const result = await handleApproval(event, api, {
    sleep: async () => undefined,
  });
  expect(api.submit).toHaveBeenCalledTimes(1);
  expect(api.submit).toHaveBeenCalledWith(
    expected.RegistryId,
    expected.RecordId,
  );
  expect(api.record).toHaveBeenCalledTimes(2);
  expect(result.Data).toEqual({
    Status: "APPROVED",
    RecordId: expected.RecordId,
  });
});

test.each([undefined, []])(
  "an exact CFN-owned record with the optional detection flag omitted and provenance %j can publish",
  async (provenance) => {
    const nativeDraft: GetRegistryRecordCommandOutput = {
      ...draft,
      provenance,
    };
    const nativeApproved: GetRegistryRecordCommandOutput = {
      ...approved,
      provenance,
    };
    delete nativeDraft.createdByAutoDetection;
    delete nativeApproved.createdByAutoDetection;
    const api = fixture([nativeDraft, nativeApproved]);
    const result = await handleApproval(event, api, {
      sleep: async () => undefined,
    });
    expect(api.submit).toHaveBeenCalledTimes(1);
    expect(result.Data?.Status).toBe("APPROVED");
  },
);

test.each([
  { createdByAutoDetection: true },
  { createdByAutoDetection: null },
  { createdByAutoDetection: "false" },
  { createdByAutoDetection: 0 },
  { createdByAutoDetection: undefined, provenance: [{}] },
  { createdByAutoDetection: false, provenance: [{}] },
  { createdByAutoDetection: undefined, provenance: null },
  { createdByAutoDetection: undefined, provenance: {} },
  { createdByAutoDetection: undefined, provenance: "" },
])("auto-detected or malformed lineage fails before submission: %j", async (changed) => {
  const record = {
    ...draft,
    ...changed,
  } as unknown as GetRegistryRecordCommandOutput;
  const api = fixture([record]);
  const failure = await handleApproval(event, api, {
    attempts: 2,
    sleep: async () => undefined,
  }).catch((error: unknown) => error);
  expect(api.submit).not.toHaveBeenCalled();
  expect(failure).toBeInstanceOf(Error);
  expect((failure as Error).message).toContain("ownership or identity");
});

test("matching APPROVED retries and updates never submit again", async () => {
  const api = fixture([approved]);
  await handleApproval({ ...event, RequestType: "Update" }, api);
  expect(api.submit).not.toHaveBeenCalled();
});

test("an unconfirmed own submission never turns deployment green", async () => {
  const api = fixture([draft]);
  await expect(
    handleApproval(event, api, { attempts: 2, sleep: async () => undefined }),
  ).rejects.toThrow("not confirmed");
  expect(api.submit).toHaveBeenCalledTimes(1);
});

test.each([
  { createdBy: "999999999999" },
  { registryArn: `${registryArn}-foreign` },
  { recordId: "foreign123456" },
  { name: "unreviewed-tool" },
  { recordType: "MCP" as const },
  { recordVersion: "3.0.0" },
  { createdByAutoDetection: true },
  { descriptors: { custom: { data: "{}" } } },
])("foreign or altered record fails before submission: %j", async (changed) => {
  const api = fixture([{ ...draft, ...changed }]);
  await expect(handleApproval(event, api)).rejects.toThrow();
  expect(api.submit).not.toHaveBeenCalled();
});

test.each([
  "PENDING_APPROVAL",
  "REJECTED",
  "DEPRECATED",
  "CREATE_FAILED",
  "UPDATE_FAILED",
] as const)(
  "%s is never accepted as an approved deployment",
  async (status) => {
    const api = fixture([{ ...draft, status }]);
    await expect(handleApproval(event, api)).rejects.toThrow(
      "not an approvable",
    );
    expect(api.submit).not.toHaveBeenCalled();
  },
);

test("wrong provenance tags and owner configuration fail before submission", async () => {
  const api = fixture();
  jest
    .mocked(api.tags)
    .mockResolvedValue({ ...expected.Tags, environment: "prod" });
  await expect(handleApproval(event, api)).rejects.toThrow("tags differ");
  expect(api.submit).not.toHaveBeenCalled();
});

test("content changed after own submission fails instead of publishing its ID", async () => {
  const api = fixture([draft, { ...approved, recordVersion: "altered" }]);
  await expect(
    handleApproval(event, api, { sleep: async () => undefined }),
  ).rejects.toThrow("ownership or identity");
  expect(api.submit).toHaveBeenCalledTimes(1);
});

test("a curator approval registry and a nonapproved catalogue cannot be auto-submitted", async () => {
  const api = fixture();
  jest.mocked(api.registry).mockResolvedValue({
    $metadata: {},
    name: "owned-registry",
    createdAt: new Date("2026-01-01T00:00:00Z"),
    updatedAt: new Date("2026-01-01T00:00:00Z"),
    registryArn,
    registryId: expected.RegistryId,
    status: "READY",
    approvalConfiguration: { autoApprovalRules: [] },
  });
  await expect(handleApproval(event, api)).rejects.toThrow(
    "automatic approval configuration",
  );
  expect(api.submit).not.toHaveBeenCalled();
  await expect(
    handleApproval(
      {
        ...event,
        ResourceProperties: {
          ...expected,
          DescriptorData: JSON.stringify({
            schemaVersion: "agenticai.tool-governance/1.0",
            toolId: "tool-echo",
            desiredApprovalStatus: "draft",
          }),
        },
      },
      api,
    ),
  ).rejects.toThrow("reviewed APPROVED catalogue");
});

test("Delete neither submits nor reads nor deletes retained governance", async () => {
  const api = fixture();
  const result = await handleApproval(
    {
      ...event,
      RequestType: "Delete",
      PhysicalResourceId: "existing-approval",
    },
    api,
  );
  expect(result).toEqual({ PhysicalResourceId: "existing-approval" });
  for (const operation of Object.values(api))
    expect(operation).not.toHaveBeenCalled();
});
