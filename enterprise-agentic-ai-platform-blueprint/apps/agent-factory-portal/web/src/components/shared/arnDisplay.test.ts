// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import { describe, expect, it } from 'vitest';
import { arnAccount, maskAccountId, maskAccountIds, maskArn } from './arnDisplay';

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

describe('maskAccountIds', () => {
  it('masks an account id that stands alone, the way an ARN shows it', () => {
    expect(maskAccountId(ACCOUNT)).toBe('••••3333');
    expect(maskAccountIds(ACCOUNT)).toBe('••••3333');
    expect(maskAccountIds(`created by ${ACCOUNT}`)).toBe('created by ••••3333');
    expect(maskAccountIds(`${ACCOUNT}, ${OTHER}`)).toBe('••••3333, ••••6666');
  });

  it('masks the account in an ARN and a bare one in the same text', () => {
    expect(maskAccountIds(`${RUNTIME} owned by ${OTHER}`)).toBe('arn:aws:bedrock-agentcore:us-east-1:••••3333:runtime/sample-abc123 owned by ••••6666');
  });

  it('masks every account id in policy text', () => {
    const cedar = `permit(principal, action, resource == AgentCore::Gateway::"arn:aws:bedrock-agentcore:eu-west-1:${ACCOUNT}:gateway/orders");`;
    expect(maskAccountIds(cedar)).not.toMatch(/\d{12}/);
    expect(maskAccountIds(cedar)).toContain('••••3333:gateway/orders');
  });

  it('leaves a longer or shorter number alone: only twelve digits are an account id', () => {
    expect(maskAccountIds(`${ACCOUNT}9`)).toBe(`${ACCOUNT}9`);
    expect(maskAccountIds('12345678901')).toBe('12345678901');
    // Thirteen digits, built at run time so no account-shaped run appears in the source.
    const epochMs = ['17000', '00000', '000'].join('');
    expect(maskAccountIds(`${epochMs} ms`)).toBe(`${epochMs} ms`);
  });

  it('is stable when applied twice', () => {
    const once = maskAccountIds(`${RUNTIME} ${OTHER}`);
    expect(maskAccountIds(once)).toBe(once);
  });

  it('leaves text without an account id unchanged', () => {
    expect(maskAccountIds('pipeline')).toBe('pipeline');
    expect(maskAccountIds('')).toBe('');
  });
});

describe('arnAccount', () => {
  it('reads the account field of an ARN, for masking and grouping only', () => {
    expect(arnAccount(RUNTIME)).toBe(ACCOUNT);
    expect(arnAccount('arn:aws:s3:::my-bucket/key')).toBe('');
    expect(arnAccount('not an arn')).toBe('');
    expect(arnAccount(null)).toBe('');
  });
});
