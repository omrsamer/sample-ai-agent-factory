/**
 * Preserve the existing S3 auto-delete custom resource on same-bucket updates.
 *
 * The CDK 2.272.0 handler uses the bucket name as its Update physical ID even
 * when Create used the request ID. Returning a different ID can cause an old
 * resource Delete. Keep the upstream behavior for deliberate bucket changes.
 *
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: MIT-0
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { Code, CfnFunction } from "aws-cdk-lib/aws-lambda";
import { Construct } from "constructs";

const UPSTREAM_SHA256 = "5fa9af527230cbfc2d2affa389d2d00676d94d335457fe323f56632160d9ad44";
const PATCHED_SHA256 = "e0e3ad10c5213030658dd9a9b21bac87c08f9007c69fa678c51d1f89590b969e";
const ORIGINAL = "PhysicalResourceId:e.ResourceProperties?.BucketName??o";
const PRESERVE_EXISTING =
  'PhysicalResourceId:typeof o==="string"&&o.length>0&&e.ResourceProperties?.BucketName===o&&typeof e.PhysicalResourceId==="string"&&e.PhysicalResourceId.length>0?e.PhysicalResourceId:e.ResourceProperties?.BucketName??o';

function digest(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

/** Rebind only the generated handler's Code; keep its role, runtime and ARN. */
export function preserveArtifactCleanupPhysicalId(provider: Construct): void {
  const handler = provider.node.tryFindChild("Handler");
  if (!handler || !CfnFunction.isCfnFunction(handler)) {
    throw new Error("Artifact cleanup: the exact generated provider Handler is required.");
  }

  const library = dirname(require.resolve("aws-cdk-lib/package.json"));
  const upstream = readFileSync(join(
    library, "custom-resource-handlers/dist/aws-s3/auto-delete-objects-handler/index.js",
  ));
  const assetPath = join(__dirname, "assets/s3-auto-delete-objects-handler");
  const patched = readFileSync(join(assetPath, "index.js"));
  const originalText = upstream.toString("utf8");
  if (digest(upstream) !== UPSTREAM_SHA256 ||
      originalText.split(ORIGINAL).length !== 2 ||
      digest(patched) !== PATCHED_SHA256 ||
      originalText.replace(ORIGINAL, PRESERVE_EXISTING) !== patched.toString("utf8")) {
    throw new Error("Artifact cleanup: unexpected provider bundle; review the compatibility patch before upgrading CDK.");
  }

  const code = Code.fromAsset(assetPath);
  const location = code.bind(handler).s3Location;
  if (!location) {
    throw new Error("Artifact cleanup: the source-owned provider must bind to an S3 code asset.");
  }
  // CDK's provider currently constructs a generic CfnResource whose type is
  // AWS::Lambda::Function. Use the public override so Code reaches the template.
  handler.addPropertyOverride("Code", {
    S3Bucket: location.bucketName,
    S3Key: location.objectKey,
    ...(location.objectVersion ? { S3ObjectVersion: location.objectVersion } : {}),
  });
  code.bindToResource(handler);
}
