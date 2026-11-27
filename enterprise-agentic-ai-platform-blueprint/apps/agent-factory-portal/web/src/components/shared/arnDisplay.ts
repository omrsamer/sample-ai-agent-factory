// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
const ARN_ACCOUNT = /\b(arn:[a-z0-9-]+:[a-z0-9-]*:[a-z0-9-]*:)(\d{12})(?=:)/g;

/** Masks the account id in every ARN in a string, keeping its last four digits. Display only. */
export function maskArn(value: string): string {
  return value.replace(ARN_ACCOUNT, (_m, head: string, account: string) => `${head}••••${account.slice(-4)}`);
}
