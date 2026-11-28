// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import { NO_READER_TITLE } from '../inventory';

/** Notes from the API about gaps in the data, plus the cost notice when cost cannot be shown. */
export function DataNotes({ notes }: { notes: string[] }) {
  if (notes.length === 0) return null;
  return (
    <div className="text-xs text-amber-900 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2" role="status">
      <ul className="space-y-0.5">
        {notes.map((n) => (
          <li key={n}>{n}</li>
        ))}
      </ul>
    </div>
  );
}

/**
 * What a tab shows for an agent in an account where the portal has no reader role. It states the
 * fact plainly: nothing failed and nothing is loading.
 */
export function NoReaderCard({ body, title = NO_READER_TITLE, more }: { body: string; title?: string; more?: string }) {
  return (
    <div className="bg-white/70 backdrop-blur rounded-xl border border-slate-200/60 shadow-sm p-5">
      <h2 className="text-sm font-semibold text-slate-900">{title}</h2>
      <p className="text-sm text-slate-700 mt-1 max-w-2xl">{body}</p>
      {more && <p className="text-sm text-slate-700 mt-1 max-w-2xl">{more}</p>}
    </div>
  );
}

export function ObsEmptyCard({ title, body, tone = 'slate' }: { title: string; body: string; tone?: 'slate' | 'amber' }) {
  const wrap = tone === 'amber' ? 'card border-amber-200 bg-amber-50/30' : 'card border-slate-200 bg-slate-50/50';
  const iconBg = tone === 'amber' ? 'bg-amber-100' : 'bg-slate-100';
  const iconFg = tone === 'amber' ? 'text-amber-600' : 'text-slate-600';
  const titleFg = tone === 'amber' ? 'text-amber-900' : 'text-slate-900';
  const bodyFg = tone === 'amber' ? 'text-amber-700/80' : 'text-slate-600';
  return (
    <div className={wrap}>
      <div className="flex items-start gap-4">
        <div className={`w-10 h-10 rounded-xl ${iconBg} flex items-center justify-center flex-shrink-0`}>
          <svg className={`w-5 h-5 ${iconFg}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M3 13.125C3 12.504 3.504 12 4.125 12h2.25c.621 0 1.125.504 1.125 1.125v6.75C7.5 20.496 6.996 21 6.375 21h-2.25A1.125 1.125 0 013 19.875v-6.75zM9.75 8.625c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125v11.25c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V8.625zM16.5 4.125c0-.621.504-1.125 1.125-1.125h2.25C20.496 3 21 3.504 21 4.125v15.75c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V4.125z" />
          </svg>
        </div>
        <div>
          <h2 className={`text-base font-semibold ${titleFg} mb-1`}>{title}</h2>
          <p className={`text-sm ${bodyFg} max-w-2xl`}>{body}</p>
        </div>
      </div>
    </div>
  );
}
