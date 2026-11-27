// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

/**
 * Runtime configuration for the Agent Factory Portal.
 *
 * The deployed site serves `/config.json`, written by infrastructure next to the bundle, so one
 * build can be promoted across environments. Nothing here is read at build time and nothing
 * throws at module load: a missing or invalid file becomes a result the entry point renders as
 * a configuration error page.
 */

export type AuthProviderName = 'cognito' | 'entra';
export type PortalEnvironment = 'nonprod' | 'prod';

export interface CognitoConfig {
  /** `https://cognito-idp.<region>.amazonaws.com/<userPoolId>` (the OIDC issuer). */
  authority: string;
  /** App client id. The API's JWT authorizer checks it as the token audience. */
  clientId: string;
  /** Hosted UI domain, `https://<prefix>.auth.<region>.amazoncognito.com`. */
  domain: string;
  scopes: string[];
}

export interface EntraConfig {
  tenantId: string;
  clientId: string;
  /** `api://<application id>/<scope name>`. */
  apiScope: string;
}

export interface RuntimeConfig {
  /** Absolute `https://…/api/v1`, or a same-origin path such as `/api/v1`. No trailing slash. */
  apiBaseUrl: string;
  authProvider: AuthProviderName;
  cognito?: CognitoConfig;
  entra?: EntraConfig;
  environment: PortalEnvironment;
  features: {
    readOnly: boolean;
    /** Governed registration and approval screens. Off unless explicitly `true`. */
    governedActions: boolean;
  };
}

export type ConfigResult =
  | { ok: true; config: RuntimeConfig; source: string }
  | { ok: false; errors: string[] };

/** Fetched in order. The second is a local-development fallback and is never part of a build. */
export const CONFIG_PATHS = ['/config.json', '/config.local.json'] as const;

const DEFAULT_COGNITO_SCOPES = ['openid', 'email', 'profile'];

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * True when a value cannot be used: empty, an unfilled `<placeholder>`, or an all-zero GUID.
 * An example value copied into a deployed file is as broken as a missing one, and is reported
 * the same way.
 */
export function isUnusableValue(raw: unknown): boolean {
  if (typeof raw !== 'string') return true;
  const value = raw.trim();
  if (value === '') return true;
  if (value.includes('<') || value.includes('>')) return true;
  return value.startsWith('00000000-0000-0000-0000-');
}

function isHttpsUrl(value: string): boolean {
  try {
    const url = new URL(value);
    if (url.protocol === 'https:') return true;
    // Plain HTTP is accepted for a loopback back end only.
    return url.protocol === 'http:' && (url.hostname === 'localhost' || url.hostname === '127.0.0.1');
  } catch {
    return false;
  }
}

function trimTrailingSlash(value: string): string {
  return value.replace(/\/+$/, '');
}

function parseCognito(raw: unknown, errors: string[]): CognitoConfig | undefined {
  if (!isRecord(raw)) {
    errors.push('cognito: required when authProvider is "cognito".');
    return undefined;
  }
  const before = errors.length;
  for (const key of ['authority', 'clientId', 'domain'] as const) {
    if (isUnusableValue(raw[key])) errors.push(`cognito.${key}: missing or still a placeholder.`);
  }
  for (const key of ['authority', 'domain'] as const) {
    const value = raw[key];
    if (typeof value === 'string' && !isUnusableValue(value) && !isHttpsUrl(value.trim())) {
      errors.push(`cognito.${key}: must be an https URL.`);
    }
  }
  let scopes = DEFAULT_COGNITO_SCOPES;
  if (raw.scopes !== undefined) {
    if (Array.isArray(raw.scopes) && raw.scopes.every((s) => typeof s === 'string' && s.trim() !== '')) {
      scopes = raw.scopes.map((s) => (s as string).trim());
    } else {
      errors.push('cognito.scopes: must be an array of non-empty strings.');
    }
  }
  if (!scopes.includes('openid')) errors.push('cognito.scopes: must include "openid".');
  if (errors.length > before) return undefined;
  return {
    authority: trimTrailingSlash((raw.authority as string).trim()),
    clientId: (raw.clientId as string).trim(),
    domain: trimTrailingSlash((raw.domain as string).trim()),
    scopes,
  };
}

function parseEntra(raw: unknown, errors: string[]): EntraConfig | undefined {
  if (!isRecord(raw)) {
    errors.push('entra: required when authProvider is "entra".');
    return undefined;
  }
  const before = errors.length;
  for (const key of ['tenantId', 'clientId', 'apiScope'] as const) {
    if (isUnusableValue(raw[key])) errors.push(`entra.${key}: missing or still a placeholder.`);
  }
  if (errors.length > before) return undefined;
  return {
    tenantId: (raw.tenantId as string).trim(),
    clientId: (raw.clientId as string).trim(),
    apiScope: (raw.apiScope as string).trim(),
  };
}

/** Validates a parsed `config.json`. Pure: no I/O, never throws. */
export function parseRuntimeConfig(raw: unknown): { config: RuntimeConfig } | { errors: string[] } {
  if (!isRecord(raw)) return { errors: ['The configuration file must contain a JSON object.'] };
  const errors: string[] = [];

  let apiBaseUrl = '';
  if (typeof raw.apiBaseUrl !== 'string' || isUnusableValue(raw.apiBaseUrl)) {
    errors.push('apiBaseUrl: missing or still a placeholder.');
  } else {
    apiBaseUrl = trimTrailingSlash(raw.apiBaseUrl.trim());
    const sameOrigin = apiBaseUrl.startsWith('/') && !apiBaseUrl.startsWith('//');
    if (!sameOrigin && !isHttpsUrl(apiBaseUrl)) {
      errors.push('apiBaseUrl: must be an https URL or a same-origin path such as "/api/v1".');
    }
  }

  const provider = raw.authProvider;
  let cognito: CognitoConfig | undefined;
  let entra: EntraConfig | undefined;
  if (provider === 'cognito') {
    cognito = parseCognito(raw.cognito, errors);
  } else if (provider === 'entra') {
    entra = parseEntra(raw.entra, errors);
  } else {
    errors.push('authProvider: must be "cognito" or "entra".');
  }

  let environment: PortalEnvironment = 'nonprod';
  if (raw.environment !== undefined) {
    if (raw.environment === 'nonprod' || raw.environment === 'prod') environment = raw.environment;
    else errors.push('environment: must be "nonprod" or "prod".');
  }

  // Milestone 1 is read-only whatever the file says; the flag is carried so later milestones
  // can gate on it. Only an explicit `false` turns it off.
  const features = isRecord(raw.features) ? raw.features : {};
  const readOnly = features.readOnly !== false;
  // The only feature that issues writes. Anything other than the boolean `true` leaves it off.
  const governedActions = features.governedActions === true;

  if (errors.length > 0) return { errors };
  return {
    config: {
      apiBaseUrl,
      authProvider: provider as AuthProviderName,
      ...(cognito ? { cognito } : {}),
      ...(entra ? { entra } : {}),
      environment,
      features: { readOnly, governedActions },
    },
  };
}

type FetchLike = (input: string, init?: { cache?: RequestCache }) => Promise<{
  ok: boolean;
  status: number;
  text: () => Promise<string>;
}>;

/**
 * Loads the first configuration file that exists and parses as JSON.
 *
 * A static host that falls back to `index.html` answers 200 with HTML for a missing file, so
 * "exists" means "parses as JSON", not "status 200". A file that parses but fails validation is
 * reported as is: falling through to the next path would hide a broken deployment behind a
 * developer's local file.
 */
export async function loadRuntimeConfig(
  fetchImpl: FetchLike = (input, init) => fetch(input, init),
  paths: readonly string[] = CONFIG_PATHS,
): Promise<ConfigResult> {
  const notes: string[] = [];
  for (const path of paths) {
    let body: string;
    try {
      const response = await fetchImpl(path, { cache: 'no-store' });
      if (!response.ok) {
        notes.push(`${path}: not found (HTTP ${response.status}).`);
        continue;
      }
      body = await response.text();
    } catch {
      notes.push(`${path}: could not be fetched.`);
      continue;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(body);
    } catch {
      notes.push(`${path}: not found, or not valid JSON.`);
      continue;
    }
    const result = parseRuntimeConfig(parsed);
    if ('errors' in result) {
      return { ok: false, errors: result.errors.map((e) => `${path} · ${e}`) };
    }
    return { ok: true, config: result.config, source: path };
  }
  return { ok: false, errors: notes };
}

let active: RuntimeConfig | null = null;

/** Called once by the entry point, after a successful load and before React renders. */
export function setRuntimeConfig(config: RuntimeConfig): void {
  active = config;
}

/** The loaded configuration, or `null` before the entry point has set it. */
export function getRuntimeConfig(): RuntimeConfig | null {
  return active;
}
