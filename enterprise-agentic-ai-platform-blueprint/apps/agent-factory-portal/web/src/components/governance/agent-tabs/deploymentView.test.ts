// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { describe, expect, it } from 'vitest';
import { agentEnvironments, deploymentActor, outcomeBadge, runtimeStatusBadge, shortSha } from './deploymentView';

describe('runtimeStatusBadge', () => {
  it('labels known statuses, tolerating case and padding', () => {
    expect(runtimeStatusBadge('READY').label).toBe('Ready');
    expect(runtimeStatusBadge(' updating ').label).toBe('Updating');
    expect(runtimeStatusBadge('create_failed').label).toBe('Create failed');
    expect(runtimeStatusBadge('not_deployed').label).toBe('Not deployed');
  });

  it('reads anything unrecognised or absent as unknown, never as ready', () => {
    for (const s of [undefined, null, '', 'ok', 'constructor', 'toString']) {
      expect(runtimeStatusBadge(s).label).toBe('Unknown');
    }
  });
});

describe('outcomeBadge', () => {
  it('labels the three outcomes and shows an unknown one as recorded', () => {
    expect(outcomeBadge('succeeded').label).toBe('Succeeded');
    expect(outcomeBadge('failed').label).toBe('Failed');
    expect(outcomeBadge('started').label).toBe('Started');
    expect(outcomeBadge('rolled_back').label).toBe('rolled_back');
    expect(outcomeBadge(undefined).label).toBe('Unknown');
  });
});

describe('deploymentActor', () => {
  it('shows a source-control login with an at sign and any other actor as recorded', () => {
    expect(deploymentActor({ actor: 'octo-dev', actor_kind: 'github' })).toBe('@octo-dev');
    expect(deploymentActor({ actor: 'pipeline-role', actor_kind: 'iam' })).toBe('pipeline-role');
  });

  it('shows a row with no actor as a dash, not as an unknown user', () => {
    expect(deploymentActor({ actor: null })).toBe('—');
    expect(deploymentActor({ actor: '  ' })).toBe('—');
  });
});

describe('agentEnvironments', () => {
  it('lists the recorded environments, sorted', () => {
    expect(agentEnvironments({ prod: 'arn:b', nonprod: 'arn:a' })).toEqual(['nonprod', 'prod']);
    expect(agentEnvironments(null)).toEqual([]);
    expect(agentEnvironments(undefined)).toEqual([]);
  });
});

describe('shortSha', () => {
  it('shortens a commit id and shows a missing one as a dash', () => {
    expect(shortSha('0123456789abcdef')).toBe('0123456');
    expect(shortSha(null)).toBe('—');
  });
});
