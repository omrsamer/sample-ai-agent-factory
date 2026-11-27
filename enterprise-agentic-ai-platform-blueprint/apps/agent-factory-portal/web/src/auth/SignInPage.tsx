// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import { useState } from 'react';
import { useAuth } from './AuthContext';

/** Neutral sign-in page. The button names the configured provider and carries no logo. */
export default function SignInPage({ environment }: { environment: string }) {
  const { signInRedirect, providerLabel, error: sessionError } = useAuth();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSignIn = async () => {
    setLoading(true);
    setError('');
    try {
      await signInRedirect();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Sign-in failed');
      setLoading(false);
    }
  };

  const shownError = error || sessionError;
  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-50 px-4">
      <main className="w-full max-w-md bg-white rounded-2xl border border-slate-200 p-10 shadow-lg">
        <div className="text-center mb-8">
          <h1 className="text-2xl font-bold text-slate-900 mb-2">Agent Factory Portal</h1>
          <p className="text-sm text-slate-500">
            Read-only view of the agent fleet, its tool gateways and the governance catalog.
          </p>
        </div>

        {shownError && (
          <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-xl text-sm text-red-700" role="alert">
            {shownError}
          </div>
        )}

        <button
          type="button"
          onClick={handleSignIn}
          disabled={loading}
          className="w-full py-3 px-4 bg-blue-600 text-white text-sm font-semibold rounded-lg hover:bg-blue-700 disabled:opacity-50 transition-all flex items-center justify-center gap-2 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2"
        >
          {loading ? 'Redirecting…' : `Sign in with ${providerLabel}`}
        </button>

        <p className="mt-6 text-xs text-center text-slate-400">Environment: {environment}</p>
      </main>
    </div>
  );
}
