// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import { useState, type ReactNode } from 'react';
import { maskArn } from './arnDisplay';

/** Shared presentational pieces used by every screen. */

export const CARD = 'bg-white/70 backdrop-blur rounded-xl border border-slate-200/60 shadow-sm';
export const PILL = 'inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium';
export const TABLE_HEAD = 'bg-slate-50/80 text-slate-500 text-xs uppercase tracking-wide';
export const TH = 'text-left font-medium px-4 py-2';
export const TD = 'px-4 py-2';
const RETRY_BTN =
  'mt-3 px-3 py-1.5 rounded-lg bg-white border border-slate-300 text-slate-700 text-xs font-medium hover:bg-slate-50 transition-colors';

export function formatDate(iso?: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export function errorMessage(err: unknown, fallback: string): string {
  return err instanceof Error && err.message ? err.message : fallback;
}

export function Page({ children, wide = true }: { children: ReactNode; wide?: boolean }) {
  return (
    <div className="min-h-full relative">
      <div className={`relative ${wide ? 'max-w-7xl' : 'max-w-4xl'} mx-auto px-6 py-8`}>{children}</div>
    </div>
  );
}

export function PageHeader({ title, subtitle, children }: { title: string; subtitle?: string; children?: ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-4 mb-6">
      <div>
        <h1 className="text-2xl font-semibold text-slate-900 tracking-tight">{title}</h1>
        {subtitle && <p className="text-sm text-slate-500 mt-0.5 max-w-3xl">{subtitle}</p>}
      </div>
      {children}
    </div>
  );
}

export function ErrorCard({ title, message, onRetry }: { title: string; message: string; onRetry?: () => void }) {
  return (
    <div className={`${CARD} border-red-200/70 p-6`} role="alert">
      <h3 className="text-sm font-semibold text-red-700">{title}</h3>
      <p className="text-sm text-slate-600 mt-1">{message}</p>
      {onRetry && (
        <button type="button" onClick={onRetry} className={RETRY_BTN}>
          Retry
        </button>
      )}
    </div>
  );
}

export function EmptyCard({ title, body }: { title: string; body: string }) {
  return (
    <div className={`${CARD} p-8 text-center`}>
      <h3 className="text-sm font-semibold text-slate-700">{title}</h3>
      <p className="text-sm text-slate-500 mt-1 max-w-2xl mx-auto">{body}</p>
    </div>
  );
}

export function Loading({ label }: { label: string }) {
  return (
    <p className="text-slate-400 text-sm" role="status">
      {label}
    </p>
  );
}

export function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <dt className="text-[11px] uppercase tracking-wide text-slate-400 font-medium">{label}</dt>
      <dd className="mt-0.5 text-sm text-slate-700">{children}</dd>
    </div>
  );
}

export function Badge({ cls, label, title }: { cls: string; label: string; title?: string }) {
  return (
    <span className={`${PILL} ${cls}`} title={title}>
      {label}
    </span>
  );
}

export function CopyButton({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false);
  const onCopy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard access denied; the value is still visible to select by hand.
    }
  };
  return (
    <button
      type="button"
      onClick={onCopy}
      aria-label={copied ? `Copied ${label}` : `Copy ${label}`}
      className="shrink-0 inline-flex items-center justify-center h-6 w-6 rounded-md text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-colors"
    >
      {copied ? (
        <svg viewBox="0 0 20 20" fill="none" className="h-3.5 w-3.5" aria-hidden="true">
          <path d="M5 10.5l3.5 3.5L15 6" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      ) : (
        <svg viewBox="0 0 20 20" fill="none" className="h-3.5 w-3.5" aria-hidden="true">
          <rect x="7" y="7" width="9" height="9" rx="1.5" stroke="currentColor" strokeWidth="1.5" />
          <path d="M13 4.5H5.5A1.5 1.5 0 004 6v7.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
        </svg>
      )}
    </button>
  );
}

/** A copyable identifier. ARNs are shown with the account id masked; the copy is the full value. */
export function CodeValue({ value, copyLabel }: { value?: string | null; copyLabel: string }) {
  if (!value) return <span className="text-sm text-slate-400">Not set</span>;
  return (
    <span className="flex items-center gap-1.5">
      <code className="text-xs font-mono text-slate-700 break-all" title={value}>
        {maskArn(value)}
      </code>
      <CopyButton value={value} label={copyLabel} />
    </span>
  );
}

export interface TabDef {
  id: string;
  label: string;
}

export function TabBar({ tabs, active, onSelect, label }: { tabs: TabDef[]; active: string; onSelect: (id: string) => void; label: string }) {
  return (
    <div className="flex items-center gap-1 mb-6 p-1 bg-slate-100/80 rounded-xl w-fit overflow-x-auto" role="tablist" aria-label={label}>
      {tabs.map((tab) => (
        <button
          key={tab.id}
          type="button"
          role="tab"
          aria-selected={active === tab.id}
          onClick={() => onSelect(tab.id)}
          className={`px-3.5 py-1.5 rounded-lg text-sm font-medium transition-all whitespace-nowrap ${
            active === tab.id ? 'bg-white text-slate-900 shadow-sm' : 'text-slate-500 hover:text-slate-700'
          }`}
        >
          {tab.label}
        </button>
      ))}
    </div>
  );
}
