// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describe, expect, it } from 'vitest';
import docsSrc from './Documentation.tsx?raw';
import { operatingRules } from './operatingRules';

describe('operatingRules', () => {
  it('states four rules either way, and the same ones except for what the portal can do in a cell', () => {
    const off = operatingRules(false);
    const on = operatingRules(true);
    expect(off).toHaveLength(4);
    expect(on).toHaveLength(4);
    expect(on.filter((rule, i) => rule !== off[i])).toHaveLength(1);
    expect(on[0]).toBe(off[0]);
    expect(on[1]).toBe('A Workstream cell is changed only by its own pipeline.');
  });

  it('says that the portal changes nothing while it is read-only', () => {
    expect(operatingRules(false)[2]).toBe(
      'Central visibility does not grant central write access. This portal never changes an agent, a tool gateway, a policy or a cell.',
    );
  });

  it('does not claim that with governed actions on: containment is named as the one exception, with its limits', () => {
    const rule = operatingRules(true)[2];
    expect(rule).not.toContain('never changes an agent');
    expect(rule).toContain('never deploys, edits or deletes');
    expect(rule).toContain('The one governed exception is containment');
    expect(rule).toContain('where a cell has given the portal that authority');
    expect(rule).toContain('It deletes nothing and a different person can release it.');
  });

  it('is what the Documentation page lists, by the feature flag', () => {
    expect(docsSrc).toContain('{operatingRules(governedActions).map((rule) => (');
    // Every approval records a review date, so the page does not say that only some approvals count as a review.
    expect(docsSrc).toContain('A registration approved through the portal has a review date: the one it names, or a year from the');
    expect(docsSrc).toContain('approval when it names none or a later one.');
    expect(docsSrc).toContain('Approving a registration counts as a review too.');
    expect(docsSrc).not.toContain('names a review date counts as a review');
  });
});
