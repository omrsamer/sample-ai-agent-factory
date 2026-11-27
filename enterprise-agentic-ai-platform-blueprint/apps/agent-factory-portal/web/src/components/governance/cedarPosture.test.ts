// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import { describe, expect, it } from 'vitest';
import tabSrc from './CedarPoliciesTab.tsx?raw';
import {
  ENFORCE_POSTURE_WARNING,
  UNKNOWN_ENFORCEMENT_VIEW,
  enforcementLabel,
  enforcementView,
  postureWarning,
  toEnforcementMode,
} from './cedarPosture';

describe('toEnforcementMode', () => {
  it('narrows the three known modes, tolerating case and padding', () => {
    expect(toEnforcementMode('enforce')).toBe('enforce');
    expect(toEnforcementMode(' LOG_ONLY ')).toBe('log_only');
    expect(toEnforcementMode('None')).toBe('none');
  });

  it('answers null for anything else, including prototype keys', () => {
    for (const raw of [undefined, null, '', 'enforced', 'disabled', 'constructor', '__proto__', 'toString']) {
      expect(toEnforcementMode(raw)).toBeNull();
    }
  });
});

describe('enforcementView', () => {
  it('describes each mode without naming per-user grants', () => {
    expect(enforcementView('none').heading).toBe('No policy engine attached');
    expect(enforcementView('log_only').heading).toBe('Logging only');
    expect(enforcementView('enforce').heading).toBe('Enforcing (default deny)');
    for (const mode of ['none', 'log_only', 'enforce']) {
      expect(enforcementView(mode).body).not.toMatch(/assigned user|every user/i);
    }
  });

  it('says log-only blocks nothing', () => {
    expect(enforcementView('log_only').body).toMatch(/nothing is blocked/);
  });

  it('never presents an unknown mode as enforcing', () => {
    expect(enforcementView('mystery')).toBe(UNKNOWN_ENFORCEMENT_VIEW);
    expect(enforcementLabel(undefined)).toBe('Enforcement mode unknown');
  });
});

describe('postureWarning', () => {
  it('warns only while enforcing', () => {
    expect(postureWarning('enforce')).toBe(ENFORCE_POSTURE_WARNING);
    expect(postureWarning('log_only')).toBeNull();
    expect(postureWarning('none')).toBeNull();
    expect(postureWarning(undefined)).toBeNull();
  });

  it('states that uncovered calls are blocked and that an empty list blocks everything', () => {
    expect(ENFORCE_POSTURE_WARNING).toMatch(/not covered by a policy below is blocked/);
    expect(ENFORCE_POSTURE_WARNING).toMatch(/empty policy list under enforcement blocks every call/);
  });
});

describe('the Policies tab', () => {
  it('is a view: no form control and no handler that changes a policy', () => {
    expect(tabSrc).not.toMatch(/<(input|select|textarea|form)\b/);
    expect(tabSrc).not.toMatch(/setEnforcement|\.add\(|\.remove\(/);
    expect(tabSrc).toContain('cannot be changed from this portal');
  });
});
