/** Stable names shared by the legacy D-03 platform and workload stacks. */
function allocationRoleName(
  tenantId: string,
  agentId: string,
  suffix: string,
): string {
  for (const value of [tenantId, agentId]) {
    if (
      typeof value !== "string" ||
      !/^[A-Za-z0-9][A-Za-z0-9-]*$/.test(value)
    ) {
      throw new Error(
        "D03 tenantId and agentId must contain only alphanumerics and hyphens.",
      );
    }
  }
  const name = `AgenticAI-D03-${tenantId}-${agentId}-${suffix}`;
  if (name.length > 64) {
    throw new Error(
      "D03 allocation role names must fit the IAM 64-character limit.",
    );
  }
  return name;
}

export function d03RuntimeRoleName(tenantId: string, agentId: string): string {
  return allocationRoleName(tenantId, agentId, "runtime");
}

export function d03BedrockCallerRoleName(
  tenantId: string,
  agentId: string,
): string {
  return allocationRoleName(tenantId, agentId, "BedrockCaller");
}
