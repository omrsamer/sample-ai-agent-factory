// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { isSafeExternalUrl } from '../governance/inventory';

export const OMNI_NOTE = 'Traces, sessions, topology and evaluations live in CloudWatch Omni.';

/**
 * Hand-off to CloudWatch Omni. A plain link that opens a new tab; nothing is embedded. Renders
 * nothing unless the API supplied an https URL.
 */
export default function OmniLink({ url, subject, compact = false }: { url: string | null | undefined; subject?: string; compact?: boolean }) {
  if (!isSafeExternalUrl(url)) return null;
  return (
    <a
      href={url}
      target="_blank"
      rel="noopener noreferrer"
      className={
        compact
          ? 'text-xs font-medium text-blue-700 underline whitespace-nowrap'
          : 'inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white border border-slate-300 text-slate-800 text-sm font-medium hover:bg-slate-50'
      }
    >
      {compact ? 'Open in Omni' : 'Open in CloudWatch Omni'}
      <span className="sr-only">
        {compact ? ' (CloudWatch Omni)' : ''}
        {subject ? `: ${subject}` : ''} (opens in a new tab)
      </span>
      <svg viewBox="0 0 20 20" fill="none" className="h-3 w-3" aria-hidden="true">
        <path d="M7 4h9v9M16 4l-9 9M4 8v8h8" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    </a>
  );
}
