// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import { describe, expect, it } from 'vitest';
import { maskArn } from './arnDisplay';

// Built at run time so no account-shaped literal appears in the source.
const ACCOUNT = ['1111', '2222', '3333'].join('');
const OTHER = ['4444', '5555', '6666'].join('');
const RUNTIME = `arn:aws:bedrock-agentcore:us-east-1:${ACCOUNT}:runtime/sample-abc123`;

describe('maskArn', () => {
  it('masks the account id, keeping its last four digits', () => {
    expect(maskArn(RUNTIME)).toBe('arn:aws:bedrock-agentcore:us-east-1:••••3333:runtime/sample-abc123');
  });

  it('masks a region-less ARN (IAM)', () => {
    expect(maskArn(`arn:aws:iam::${ACCOUNT}:role/deploy`)).toBe('arn:aws:iam::••••3333:role/deploy');
  });

  it('masks every ARN inside a longer string', () => {
    const two = `${RUNTIME} and arn:aws-us-gov:iam::${OTHER}:role/x`;
    expect(maskArn(two)).toBe(
      'arn:aws:bedrock-agentcore:us-east-1:••••3333:runtime/sample-abc123 and arn:aws-us-gov:iam::••••6666:role/x',
    );
  });

  it('leaves an ARN without an account id unchanged (S3)', () => {
    expect(maskArn('arn:aws:s3:::my-bucket/key')).toBe('arn:aws:s3:::my-bucket/key');
  });

  it('leaves non-ARN strings unchanged', () => {
    expect(maskArn('https://gw.example.com/mcp')).toBe('https://gw.example.com/mcp');
    expect(maskArn('')).toBe('');
  });

  it('does not mask a 12-digit run that is not the account field', () => {
    expect(maskArn(`arn:aws:sqs:us-east-1:${ACCOUNT}:q-${OTHER}`)).toBe(
      `arn:aws:sqs:us-east-1:••••3333:q-${OTHER}`,
    );
  });
});
