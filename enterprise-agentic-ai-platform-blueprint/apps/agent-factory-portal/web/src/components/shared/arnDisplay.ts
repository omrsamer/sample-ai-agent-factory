// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
const ARN_ACCOUNT = /\b(arn:[a-z0-9-]+:[a-z0-9-]*:[a-z0-9-]*:)(\d{12})(?=:)/g;
// A number of exactly twelve digits that stands alone: not part of a longer number.
const BARE_ACCOUNT = /(^|[^\d•])(\d{12})(?!\d)/g;

/** An account id reduced to its last four digits, the way it is shown inside an ARN. */
export function maskAccountId(account: string): string {
  return `••••${account.slice(-4)}`;
}

/** Masks the account id in every ARN in a string, keeping its last four digits. Display only. */
export function maskArn(value: string): string {
  return value.replace(ARN_ACCOUNT, (_m, head: string, account: string) => `${head}${maskAccountId(account)}`);
}

/**
 * Masks every account id in a text: the ones inside ARNs and any other twelve-digit number that
 * stands alone. No page shows an account id in full; a copy button still copies the real value.
 */
export function maskAccountIds(value: string): string {
  return maskArn(value).replace(BARE_ACCOUNT, (_m, before: string, account: string) => `${before}${maskAccountId(account)}`);
}

const ARN_ACCOUNT_FIELD = /^arn:[^:]*:[^:]*:[^:]*:(\d{12}):/;

/** The account id an ARN names, or an empty string. For masking and grouping only, never for display. */
export function arnAccount(arn: string | null | undefined): string {
  return ARN_ACCOUNT_FIELD.exec(arn ?? '')?.[1] ?? '';
}
