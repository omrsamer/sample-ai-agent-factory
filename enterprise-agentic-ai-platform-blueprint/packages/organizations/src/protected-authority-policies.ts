/**
 * Pack the reviewed authority protections for exact account attachments.
 *
 * Shared by the management app and the live Sandbox twin so no deployment
 * path installs a business exception without the same protection documents.
 */
import {
  renderProtectedAuthorityStatements,
  validateProtectedAuthorityManifest,
} from "./protected-authority";
import {
  SCP_BODY_SOFT_LIMIT,
  SCP_MAX_ATTACHED_PER_TARGET,
  toScpDefinition,
  type ScpDefinition,
} from "./scps";

export interface ProtectedAuthorityPolicy extends ScpDefinition {
  readonly accountId: string;
}

export function buildProtectedAuthorityPolicies(
  raw: unknown,
): readonly ProtectedAuthorityPolicy[] {
  const validated = validateProtectedAuthorityManifest(raw);
  const manifest = {
    ...validated,
    roles: [...validated.roles].sort((a, b) => a.id.localeCompare(b.id)),
    resources: [...validated.resources].sort((a, b) =>
      a.id.localeCompare(b.id),
    ),
  };
  const policies: ProtectedAuthorityPolicy[] = [];
  for (const accountId of [...manifest.governedAccountIds].sort()) {
    const chunks: Record<string, unknown>[][] = [];
    let current: Record<string, unknown>[] = [];
    for (const statement of renderProtectedAuthorityStatements(
      manifest,
      accountId,
    )) {
      const next = [...current, statement];
      if (
        JSON.stringify({ Version: "2012-10-17", Statement: next }).length >
        SCP_BODY_SOFT_LIMIT
      ) {
        if (current.length === 0) {
          throw new Error(
            "A protected authority statement exceeds the SCP body limit.",
          );
        }
        chunks.push(current);
        current = [statement];
        if (
          JSON.stringify({ Version: "2012-10-17", Statement: current }).length >
          SCP_BODY_SOFT_LIMIT
        ) {
          throw new Error(
            "A protected authority statement exceeds the SCP body limit.",
          );
        }
      } else {
        current = next;
      }
    }
    if (current.length > 0) chunks.push(current);
    if (
      chunks.length === 0 ||
      chunks.length > SCP_MAX_ATTACHED_PER_TARGET - 1
    ) {
      throw new Error(
        `Protected authority policies for ${accountId} must fit the direct account SCP quota, including FullAWSAccess. Use dedicated protected deployment roles and reduce the governed authority surface.`,
      );
    }
    for (const [index, statements] of chunks.entries()) {
      const id = `authority-${accountId}-${index + 1}`;
      policies.push({
        ...toScpDefinition(
          id,
          `AgenticAI-ProtectedAuthority-${accountId}-${index + 1}`,
          `Protect reviewed deployment authority, manifest epoch ${manifest.epoch}.`,
          { Version: "2012-10-17", Statement: statements },
        ),
        accountId,
      });
    }
  }
  return policies;
}
