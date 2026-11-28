// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describe, expect, it } from 'vitest';
import { downloadFilename, evidenceFilename } from './download';

describe('downloadFilename', () => {
  it('uses the name the server sent', () => {
    expect(downloadFilename('attachment; filename="agent-evidence-orders-assistant-2026-11-27.json"', 'agent-evidence.json')).toBe(
      'agent-evidence-orders-assistant-2026-11-27.json',
    );
    expect(downloadFilename("attachment; filename*=UTF-8''agent%20evidence.json", 'agent-evidence.json')).toBe('agent evidence.json');
  });

  it('falls back to the given name when the header is absent or names nothing', () => {
    expect(downloadFilename(null, 'agent-evidence.json')).toBe('agent-evidence.json');
    expect(downloadFilename('attachment', 'agent-evidence.json')).toBe('agent-evidence.json');
    expect(downloadFilename('attachment; filename=""', 'agents.csv')).toBe('agents.csv');
  });

  it('builds the evidence file name the API would give, for when its header cannot be read', () => {
    const now = new Date('2026-11-28T23:59:59Z');
    expect(evidenceFilename('orders-assistant', 'AbC123', now)).toBe('agent-evidence-orders-assistant-2026-11-28.json');
    // Reduced to letters, digits, ".", "_" and "-", like the API's own name.
    expect(evidenceFilename('a"; x\r\nSet-Cookie: y', 'id', now)).toBe('agent-evidence-a-x-Set-Cookie-y-2026-11-28.json');
    expect(evidenceFilename('../..', 'runtime_1-AbCd', now)).toBe('agent-evidence-runtime_1-AbCd-2026-11-28.json');
    expect(evidenceFilename('', null, now)).toBe('agent-evidence-agent-2026-11-28.json');
    expect(evidenceFilename('x'.repeat(100), 'id', now)).toBe(`agent-evidence-${'x'.repeat(64)}-2026-11-28.json`);
    // The date is counted in UTC, as the API counts it.
    expect(evidenceFilename('a', 'a', new Date('2026-11-28T00:00:01+02:00'))).toBe('agent-evidence-a-2026-11-27.json');
  });

  it('keeps only a safe base name', () => {
    expect(downloadFilename('attachment; filename="../../etc/passwd"', 'x.json')).toBe('passwd');
    expect(downloadFilename('attachment; filename="a<b>c:d.json"', 'x.json')).toBe('a_b_c_d.json');
    expect(downloadFilename('attachment; filename=".hidden"', 'x.json')).toBe('hidden');
  });
});
