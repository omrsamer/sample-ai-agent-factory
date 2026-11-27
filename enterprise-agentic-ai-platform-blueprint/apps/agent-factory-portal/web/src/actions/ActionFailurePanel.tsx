// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import type { ActionFailure } from './registrationsClient';

const BTN = 'mt-3 px-3 py-1.5 rounded-lg bg-white border border-slate-300 text-slate-700 text-xs font-medium hover:bg-slate-50';

/** Shows a failed action: what kind of refusal it was and the server's own explanation. */
export default function ActionFailurePanel({ failure, onRefresh }: { failure: ActionFailure | null; onRefresh?: () => void }) {
  if (!failure) return null;
  return (
    <div className="rounded-xl border border-red-200 bg-red-50 p-4" role="alert">
      <h2 className="text-sm font-semibold text-red-800">{failure.title}</h2>
      {failure.message && <p className="text-sm text-red-800 mt-1 break-words">{failure.message}</p>}
      {failure.otherErrors.length > 0 && (
        <ul className="mt-1 list-disc list-inside text-sm text-red-800">
          {failure.otherErrors.map((e) => (
            <li key={e} className="break-words">{e}</li>
          ))}
        </ul>
      )}
      {failure.kind === 'validation' && Object.keys(failure.fieldErrors).length > 0 && (
        <p className="text-sm text-red-800 mt-1">The fields that need attention are marked below.</p>
      )}
      {failure.hint && <p className="text-sm text-red-800 mt-1 break-words">{failure.hint}</p>}
      {failure.kind === 'unavailable' && <p className="text-sm text-red-800 mt-1">You can try again.</p>}
      {failure.requestId && (
        <p className="text-xs text-red-800 mt-2">
          Recorded in the audit trail. Reference: <span className="font-mono break-all">{failure.requestId}</span>
        </p>
      )}
      {failure.kind === 'conflict' && onRefresh && (
        <>
          <p className="text-sm text-red-800 mt-1">Refresh to see the record’s current state.</p>
          <button type="button" className={BTN} onClick={onRefresh}>
            Refresh
          </button>
        </>
      )}
    </div>
  );
}
