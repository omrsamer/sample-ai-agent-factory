// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import type { UserTenant } from '../../api/client';

/** Display name for a tenant id, from the caller's own memberships. `null` when unknown. */
export function resolveTenantName(
  id: string | null | undefined,
  ...directories: (UserTenant[] | null | undefined)[]
): string | null {
  if (!id) return null;
  for (const dir of directories) {
    const hit = dir?.find((t) => t.id === id);
    if (hit) return hit.name;
  }
  return null;
}

export function tenantNames(tenants: UserTenant[]): string {
  return tenants.map((t) => t.name).join(', ');
}
