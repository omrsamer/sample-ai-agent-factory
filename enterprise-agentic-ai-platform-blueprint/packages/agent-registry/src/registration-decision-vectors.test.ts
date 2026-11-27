/**
 * Shared decision vectors for the registration authorization core.
 *
 * `packages/agent-registry/vectors/registration-decisions.json` is read by two
 * implementations: this TypeScript core and the Python port the Agent Factory
 * Portal's registrar and approver functions run
 * (`apps/agent-factory-portal/api/portal_api/registration_core.py`). Each side
 * runs every vector, so the two cannot drift apart silently.
 *
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: MIT-0
 */
import * as fs from 'fs';
import * as path from 'path';

import {
  RegistrationRecordState,
  RegistrationRequest,
  evaluateRegistrationRequest,
} from './agent-registration-api';

interface Vector {
  readonly name: string;
  readonly principal: unknown;
  readonly action: string;
  readonly request: Record<string, unknown> | null;
  readonly currentState: RegistrationRecordState | null;
  readonly expected: { readonly allowed: boolean; readonly reasonContains?: string };
}

const vectors: Vector[] = JSON.parse(
  fs.readFileSync(path.resolve(__dirname, '..', 'vectors', 'registration-decisions.json'), 'utf8'),
);

describe('registration decision vectors (shared with the Python port)', () => {
  it('covers every action and both outcomes', () => {
    const actions = new Set(vectors.map((v) => v.action));
    for (const action of ['create', 'update', 'approve', 'delete']) expect(actions).toContain(action);
    expect(vectors.some((v) => v.expected.allowed)).toBe(true);
    expect(vectors.some((v) => !v.expected.allowed)).toBe(true);
    expect(new Set(vectors.map((v) => v.name)).size).toBe(vectors.length);
  });

  it.each(vectors.map((v) => [v.name, v] as const))('%s', (_name, vector) => {
    const request = {
      ...(vector.request ?? {}),
      action: vector.action,
      principal: vector.principal,
    } as unknown as RegistrationRequest;
    const decision = evaluateRegistrationRequest(request, vector.currentState ?? undefined);
    expect(decision.decision === 'allow').toBe(vector.expected.allowed);
    if (vector.expected.reasonContains) {
      expect(decision.reason).toContain(vector.expected.reasonContains);
    }
    if (decision.decision === 'deny') expect(decision.httpStatus).toBe(403);
  });
});
