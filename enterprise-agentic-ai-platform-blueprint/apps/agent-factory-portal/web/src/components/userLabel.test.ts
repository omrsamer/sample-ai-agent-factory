// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describe, expect, it } from 'vitest';
import { userEmail, userLabel } from './userLabel';

const SUBJECT = 'a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d';

describe('userLabel', () => {
  it('prefers the display name from the API, then its name, then its email', () => {
    expect(userLabel({ display_name: 'Example Reviewer', name: 'x', email: 'r@example.com' }, null)).toBe('Example Reviewer');
    expect(userLabel({ display_name: null, name: 'Reviewer', email: 'r@example.com' }, null)).toBe('Reviewer');
    expect(userLabel({ name: '  ', email: 'r@example.com' }, null)).toBe('r@example.com');
  });

  it('never shows a token subject, wherever it arrives', () => {
    expect(userLabel({ display_name: SUBJECT, name: SUBJECT, email: 'r@example.com' }, { username: SUBJECT })).toBe('r@example.com');
    expect(userLabel({ name: SUBJECT }, { name: SUBJECT, username: SUBJECT })).toBe('Signed in');
  });

  it('falls back to what the identity provider supplied when the API read failed', () => {
    expect(userLabel(null, { name: 'Provider Name', username: 'p@example.com' })).toBe('Provider Name');
    expect(userLabel(null, { username: 'p@example.com' })).toBe('p@example.com');
    expect(userLabel(null, null)).toBe('Signed in');
  });
});

describe('userEmail', () => {
  it('returns an address only when one is known', () => {
    expect(userEmail({ email: 'r@example.com' }, null)).toBe('r@example.com');
    expect(userEmail(null, { username: 'p@example.com' })).toBe('p@example.com');
    expect(userEmail(null, { username: SUBJECT })).toBeNull();
    expect(userEmail({ email: 'not-an-address' }, null)).toBeNull();
  });
});
