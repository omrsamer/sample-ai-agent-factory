// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import { lazy, Suspense } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, Link } from 'react-router-dom';
import { useAuth } from './auth/AuthContext';
import { AUTH_CALLBACK_PATH } from './auth/authShape';
import type { AuthProviderComponent } from './auth/providerSelection';
import SignInPage from './auth/SignInPage';
import type { RuntimeConfig } from './config/runtimeConfig';
import { UserProvider } from './contexts/UserContext';
import Sidebar from './components/Sidebar';
import Fleet from './components/Fleet';
import Documentation from './components/Documentation';
import ReleaseEvidence from './components/ReleaseEvidence';
import AgentsList from './components/governance/AgentsList';
import ToolGateways from './components/governance/ToolGateways';
import McpServerDetail from './components/governance/McpServerDetail';
import GovernanceCatalog from './components/catalog/GovernanceCatalog';
import { Loading, Page } from './components/shared/ui';

// The charting and graph libraries are large; screens that use them load on first visit.
const Observability = lazy(() => import('./components/Observability'));
const AgentDetail = lazy(() => import('./components/governance/AgentDetail'));
const GovernanceGraph = lazy(() => import('./components/governance/GovernanceGraph'));

function RouteFallback() {
  return (
    <Page>
      <Loading label="Loading…" />
    </Page>
  );
}

function NotFound() {
  return (
    <Page>
      <h1 className="text-2xl font-semibold text-slate-900">Page not found</h1>
      <p className="text-sm text-slate-500 mt-2">
        That address is not part of the portal.{' '}
        <Link to="/" className="text-blue-700 hover:underline">Back to the fleet</Link>.
      </p>
    </Page>
  );
}

function AuthGate({ config }: { config: RuntimeConfig }) {
  const { isAuthenticated, isLoading, postSignInPath } = useAuth();

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-50">
        <div className="text-slate-400 text-sm" role="status">Loading…</div>
      </div>
    );
  }

  if (!isAuthenticated) return <SignInPage environment={config.environment} />;

  return (
    <UserProvider>
      <div className="h-screen flex overflow-hidden">
        <Sidebar environment={config.environment} />
        <main className="flex-1 overflow-y-auto relative">
          <div className="portal-backdrop fixed inset-0 pointer-events-none z-0" aria-hidden="true" />
          <div className="relative h-full">
            <Suspense fallback={<RouteFallback />}>
            <Routes>
              {/* Assurance and operations */}
              <Route path="/" element={<Fleet />} />
              <Route path="/agents" element={<AgentsList />} />
              <Route path="/agents/:id" element={<AgentDetail />} />
              <Route path="/tool-gateways" element={<ToolGateways />} />
              <Route path="/tool-gateways/:id" element={<McpServerDetail />} />
              <Route path="/access-graph" element={<GovernanceGraph />} />
              <Route path="/observability" element={<Observability />} />
              <Route path="/release-evidence" element={<ReleaseEvidence />} />
              <Route path="/release-evidence/:agentId" element={<ReleaseEvidence />} />
              {/* Platform control */}
              <Route path="/catalog" element={<Navigate to="/catalog/agents" replace />} />
              <Route path="/catalog/:section" element={<GovernanceCatalog />} />
              {/* Resources */}
              <Route path="/docs" element={<Documentation />} />
              {/* The sign-in redirect lands here; the provider has already consumed it. */}
              <Route path={AUTH_CALLBACK_PATH} element={<Navigate to={postSignInPath} replace />} />
              <Route path="*" element={<NotFound />} />
            </Routes>
            </Suspense>
          </div>
        </main>
      </div>
    </UserProvider>
  );
}

export default function App({ config, AuthProvider }: { config: RuntimeConfig; AuthProvider: AuthProviderComponent }) {
  return (
    <AuthProvider>
      <Router>
        <AuthGate config={config} />
      </Router>
    </AuthProvider>
  );
}
