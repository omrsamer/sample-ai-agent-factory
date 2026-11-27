// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

interface ApiUser {
  display_name?: string | null;
  name?: string | null;
  email?: string | null;
}

interface ProviderUser {
  name?: string;
  username?: string;
}

const OPAQUE_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** A value fit to show as a person's label: non-empty and not an opaque subject identifier. */
function usable(value: string | null | undefined): string | null {
  const trimmed = value?.trim();
  if (!trimmed || OPAQUE_ID.test(trimmed)) return null;
  return trimmed;
}

/**
 * The label shown for the signed-in user: the API's display name, then its name, then an email
 * address, then what the identity provider supplied. A token subject is never shown; when
 * nothing usable exists the label is "Signed in".
 */
export function userLabel(apiUser: ApiUser | null | undefined, providerUser: ProviderUser | null | undefined): string {
  return (
    usable(apiUser?.display_name) ??
    usable(apiUser?.name) ??
    usable(apiUser?.email) ??
    usable(providerUser?.name) ??
    usable(providerUser?.username) ??
    'Signed in'
  );
}

/** The email line of the profile menu, or null when no address is known. */
export function userEmail(apiUser: ApiUser | null | undefined, providerUser: ProviderUser | null | undefined): string | null {
  const candidate = usable(apiUser?.email) ?? usable(providerUser?.username);
  return candidate && candidate.includes('@') ? candidate : null;
}
