// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

/** Shown instead of the application when `/config.json` is missing or invalid. */
export default function ConfigErrorPage({ errors }: { errors: string[] }) {
  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-50 px-4">
      <main className="w-full max-w-xl bg-white rounded-2xl border border-slate-200 p-8 shadow-sm">
        <h1 className="text-xl font-semibold text-slate-900">Agent Factory Portal is not configured</h1>
        <p className="text-sm text-slate-600 mt-2">
          The portal reads its settings from <code className="font-mono text-xs">/config.json</code>, which
          the deployment writes next to the site. That file is missing or invalid, so the portal
          cannot sign you in or reach the API.
        </p>
        <ul className="mt-4 space-y-1.5 text-sm text-red-700 list-disc list-inside" role="alert">
          {errors.map((e) => (
            <li key={e} className="break-words">{e}</li>
          ))}
        </ul>
        <p className="text-xs text-slate-500 mt-5">
          Running locally? Copy <code className="font-mono">public/config.example.json</code> to{' '}
          <code className="font-mono">public/config.local.json</code>, fill in the values, and reload.
        </p>
      </main>
    </div>
  );
}
