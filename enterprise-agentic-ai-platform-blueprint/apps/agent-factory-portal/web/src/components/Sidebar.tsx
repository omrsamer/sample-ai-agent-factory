// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import { Link, useLocation } from 'react-router-dom';
import { useEffect, useRef, useState } from 'react';
import { useAuth } from '../auth/AuthContext';
import { useUser } from '../contexts/UserContext';
import { PORTAL_NAV, isNavItemActive } from './nav';
import { emailAlias, initialsFor } from './governance/agentUi';
import { tenantNames } from './governance/tenantUi';

const ENVIRONMENT_BADGE: Record<string, string> = {
  prod: 'bg-rose-50 text-rose-700 border-rose-200',
  nonprod: 'bg-slate-100 text-slate-600 border-slate-200',
};

export default function Sidebar({ environment }: { environment: string }) {
  const location = useLocation();
  const { signOut, user: authUser } = useAuth();
  const { user: currentUser } = useUser();
  const [profileOpen, setProfileOpen] = useState(false);
  const [isCollapsed, setIsCollapsed] = useState(false);
  const profileRef = useRef<HTMLDivElement>(null);

  // The back end's view of the caller wins; the identity provider's is the fallback.
  const displayName =
    currentUser?.name?.trim() || authUser?.name?.trim() || emailAlias(currentUser?.email ?? authUser?.username);
  const displayRole = currentUser?.role ?? '';
  const displayTenants = tenantNames(currentUser?.tenants ?? []);
  const groups = authUser?.groups ?? [];

  useEffect(() => {
    if (!profileOpen) return;
    const onPointerDown = (e: MouseEvent) => {
      if (profileRef.current && !profileRef.current.contains(e.target as Node)) setProfileOpen(false);
    };
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setProfileOpen(false);
    };
    document.addEventListener('mousedown', onPointerDown);
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('mousedown', onPointerDown);
      document.removeEventListener('keydown', onKeyDown);
    };
  }, [profileOpen]);

  return (
    <aside
      className={`relative flex flex-col h-screen bg-white border-r border-slate-200 transition-all duration-300 ${
        isCollapsed ? 'w-16' : 'w-64'
      }`}
      aria-label="Primary"
    >
      <div className={`px-4 pt-5 pb-4 border-b border-slate-200 flex items-center gap-2.5 ${isCollapsed ? 'justify-center' : ''}`}>
        <Link to="/" className="flex items-center gap-2.5 min-w-0" aria-label="Agent Factory Portal home">
          <span className="flex-shrink-0 h-8 w-8 rounded-lg bg-blue-600 text-white flex items-center justify-center text-[11px] font-bold tracking-tight" aria-hidden="true">
            AF
          </span>
          {!isCollapsed && (
            <span className="min-w-0">
              <span className="block text-sm font-semibold text-slate-900 leading-tight tracking-tight truncate">
                Agent Factory Portal
              </span>
              <span className={`inline-block mt-0.5 px-1.5 py-px rounded border text-[10px] font-medium uppercase tracking-wide ${ENVIRONMENT_BADGE[environment] ?? ENVIRONMENT_BADGE.nonprod}`}>
                {environment} · read-only
              </span>
            </span>
          )}
        </Link>
      </div>

      <nav className="flex-1 overflow-y-auto px-3 py-3 space-y-4" aria-label="Sections">
        {PORTAL_NAV.map((section) => (
          <div key={section.id}>
            {!isCollapsed && (
              <h2 className="px-3 pb-1 text-[10px] font-semibold uppercase tracking-wider text-slate-400">{section.label}</h2>
            )}
            <ul className="space-y-0.5">
              {section.items.map((item) => {
                const active = isNavItemActive(item, location.pathname);
                return (
                  <li key={item.to}>
                    <Link
                      to={item.to}
                      title={isCollapsed ? item.label : undefined}
                      aria-current={active ? 'page' : undefined}
                      className={`flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                        active ? 'bg-blue-50 text-blue-700' : 'text-slate-600 hover:bg-slate-50 hover:text-slate-900'
                      } ${isCollapsed ? 'justify-center' : ''}`}
                    >
                      <svg className="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5} aria-hidden="true">
                        <path strokeLinecap="round" strokeLinejoin="round" d={item.icon} />
                      </svg>
                      {isCollapsed ? <span className="sr-only">{item.label}</span> : <span className="truncate">{item.label}</span>}
                    </Link>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </nav>

      <div className="px-3 py-2 border-t border-slate-200">
        <button
          type="button"
          onClick={() => setIsCollapsed((v) => !v)}
          aria-expanded={!isCollapsed}
          aria-label={isCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          className={`w-full flex items-center gap-2.5 px-3 py-1.5 rounded-lg text-xs text-slate-500 hover:bg-slate-50 ${isCollapsed ? 'justify-center' : ''}`}
        >
          <svg className={`w-3.5 h-3.5 transition-transform ${isCollapsed ? 'rotate-180' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} aria-hidden="true">
            <path strokeLinecap="round" strokeLinejoin="round" d="M15 19l-7-7 7-7" />
          </svg>
          {!isCollapsed && <span>Collapse</span>}
        </button>
      </div>

      <div className="border-t border-slate-200 px-3 py-3" ref={profileRef}>
        <button
          type="button"
          onClick={() => setProfileOpen((v) => !v)}
          aria-expanded={profileOpen}
          aria-haspopup="true"
          className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-lg hover:bg-slate-50 transition-colors ${isCollapsed ? 'justify-center' : ''}`}
          title={displayRole ? `${displayName} · ${displayRole}` : displayName}
        >
          <span className="w-7 h-7 rounded-full bg-blue-100 text-blue-700 text-xs font-semibold flex items-center justify-center flex-shrink-0" aria-hidden="true">
            {initialsFor(displayName)}
          </span>
          {!isCollapsed && (
            <span className="min-w-0 flex-1 text-left">
              <span className="block text-sm font-medium text-slate-900 truncate">{displayName}</span>
              {displayRole && <span className="block text-xs text-slate-500 capitalize truncate">{displayRole}</span>}
            </span>
          )}
        </button>
        {profileOpen && (
          <div className="mt-1 bg-white rounded-xl border border-slate-200 py-1.5 shadow-lg">
            <div className="px-4 py-2 border-b border-slate-100 space-y-0.5">
              <div className="text-xs font-semibold text-slate-900 break-all">{currentUser?.email ?? authUser?.username}</div>
              {displayRole && <div className="text-xs text-slate-500 capitalize">Role: {displayRole}</div>}
              {displayTenants && <div className="text-xs text-slate-500">Tenants: {displayTenants}</div>}
              {groups.length > 0 && <div className="text-xs text-slate-500">Groups: {groups.join(', ')}</div>}
            </div>
            <button
              type="button"
              onClick={signOut}
              className="w-full flex items-center px-4 py-2 text-sm text-red-600 hover:bg-red-50 gap-2.5"
            >
              <svg className="w-4 h-4 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5} aria-hidden="true">
                <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 9V5.25A2.25 2.25 0 0013.5 3h-6a2.25 2.25 0 00-2.25 2.25v13.5A2.25 2.25 0 007.5 21h6a2.25 2.25 0 002.25-2.25V15m3 0l3-3m0 0l-3-3m3 3H9" />
              </svg>
              Sign out
            </button>
          </div>
        )}
      </div>
    </aside>
  );
}
