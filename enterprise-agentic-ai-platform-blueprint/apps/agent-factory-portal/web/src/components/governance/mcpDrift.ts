// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
/**
 * Compares the tool gateways an agent's descriptor declares with the ones it is subscribed to.
 * An agent that declares nothing is treated as declaring everything it is subscribed to.
 */
export type DriftState = 'connected' | 'not_granted' | 'unused_grant';

export function computeDrift(
  declared: string[] | undefined,
  granted: string[],
): { id: string; state: DriftState }[] {

  const known = declared && declared.length > 0 ? new Set(declared) : null;
  const grantedSet = new Set(granted);
  const rows = [...grantedSet].map((id) => ({
    id,
    state: (!known || known.has(id) ? 'connected' : 'unused_grant') as DriftState,
  }));
  for (const id of known ?? []) {
    if (!grantedSet.has(id)) rows.push({ id, state: 'not_granted' });
  }
  return rows;
}
