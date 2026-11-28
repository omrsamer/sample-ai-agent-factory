// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

/**
 * Saving a file that was fetched with the bearer token. A token cannot be put in a link, so a
 * download is a request like any other, whose answer the browser is then asked to save.
 */

const FILENAME_STAR = /filename\*\s*=\s*([^']*)'[^']*'([^;]+)/i;
const FILENAME = /filename\s*=\s*(?:"([^"]*)"|([^;]+))/i;

/**
 * The file name the server gave in `Content-Disposition`, reduced to a safe base name. Falls
 * back to `fallback` when the header is absent, unreadable or names nothing usable.
 */
export function downloadFilename(contentDisposition: string | null | undefined, fallback: string): string {
  if (!contentDisposition) return fallback;
  let name = '';
  const star = FILENAME_STAR.exec(contentDisposition);
  if (star) {
    try {
      name = decodeURIComponent(star[2].trim());
    } catch {
      name = '';
    }
  }
  if (!name) {
    const plain = FILENAME.exec(contentDisposition);
    name = (plain?.[1] ?? plain?.[2] ?? '').trim();
  }
  // Keep the last path segment only, and only characters that are safe in a file name.
  name = name.split(/[\\/]/).pop() ?? '';
  name = name.replace(/[^A-Za-z0-9._ -]/g, '_').replace(/^\.+/, '');
  return name || fallback;
}

const UNSAFE_IN_NAME = /[^A-Za-z0-9._-]+/g;
const EDGES = /^[-.]+|[-.]+$/g;

/**
 * The name the API gives an agent's evidence file, `agent-evidence-<agent name>-<UTC date>.json`,
 * built here for the case that its `Content-Disposition` header cannot be read. The agent's
 * name, else its id, is reduced to letters, digits, `.`, `_` and `-`, as the API does.
 */
export function evidenceFilename(agentName: string | null | undefined, agentId: string | null | undefined, now: Date): string {
  const safe = [agentName, agentId]
    .map((candidate) => (candidate ?? '').replace(UNSAFE_IN_NAME, '-').replace(EDGES, '').slice(0, 64).replace(EDGES, ''))
    .find((candidate) => candidate !== '');
  return `agent-evidence-${safe ?? 'agent'}-${now.toISOString().slice(0, 10)}.json`;
}

/** Hands a fetched file to the browser. The object URL is released once the download has been taken. */
export function saveFile(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}
