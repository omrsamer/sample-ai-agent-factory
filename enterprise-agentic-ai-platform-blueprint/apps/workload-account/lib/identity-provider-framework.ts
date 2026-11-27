/*
 * Binds the reviewed once-only Source transport to the existing CDK Provider.
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: MIT-0
 */
import { Stack } from "aws-cdk-lib";
import { CfnFunction, Code, Function as LambdaFunction } from "aws-cdk-lib/aws-lambda";
import { Provider } from "aws-cdk-lib/custom-resources";
import { Construct } from "constructs";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";

export const IDENTITY_PROVIDER_FRAMEWORK_ZIP_SHA256 =
  "7159e2e5244e904d22b215956c3c06a787963448d470ea66f9df7ebf4f4d7e1d";

function reviewedArtifact(): string {
  let directory = __dirname;
  while (true) {
    const packagePath = join(directory, "package.json");
    if (existsSync(packagePath)) {
      const pkg = JSON.parse(readFileSync(packagePath, "utf8")) as { name?: string };
      if (pkg.name === "enterprise-agentic-ai-platform-blueprint") {
        const artifact = join(directory, "assets", "identity-provider-framework.zip");
        if (createHash("sha256").update(readFileSync(artifact)).digest("hex") !==
            IDENTITY_PROVIDER_FRAMEWORK_ZIP_SHA256) {
          throw new Error("The reviewed identity Provider framework ZIP bytes differ.");
        }
        return artifact;
      }
    }
    const parent = dirname(directory);
    if (parent === directory) {
      throw new Error("The blueprint source root for the reviewed Provider framework is absent.");
    }
    directory = parent;
  }
}

/** Preserve the existing Provider function, IAM, handler and service token. */
export function bindReviewedIdentityProviderFramework(provider: Provider): void {
  if (provider.isCompleteHandler !== undefined ||
      provider.node.tryFindChild("ReviewedFrameworkCode") !== undefined) {
    throw new Error("The reviewed framework supports one onEvent-only Provider binding.");
  }
  const functions = provider.node.findAll().filter(
    (node): node is LambdaFunction => node instanceof LambdaFunction,
  );
  if (functions.length !== 1) {
    throw new Error("The identity Provider must own exactly its existing framework function.");
  }
  const resource = functions[0].node.defaultChild;
  if (!(resource instanceof CfnFunction) || resource.handler !== "framework.onEvent" ||
      resource.runtime !== "nodejs24.x") {
    throw new Error("The existing Provider framework handler/runtime differs from the reviewed ZIP.");
  }
  const stack = Stack.of(provider);
  const environment = stack.resolve(resource.environment) as { variables?: Record<string, unknown> };
  if (!environment.variables ||
      Object.keys(environment.variables).sort().join(",") !== "USER_ON_EVENT_FUNCTION_ARN" ||
      JSON.stringify(environment.variables.USER_ON_EVENT_FUNCTION_ARN) !==
      JSON.stringify(stack.resolve(provider.onEventHandler.functionArn))) {
    throw new Error("The Provider framework must invoke only its exact original Source handler.");
  }
  const artifact = reviewedArtifact();
  const code = Code.fromAsset(artifact);
  const bound = code.bind(new Construct(provider, "ReviewedFrameworkCode"));
  if (!bound.s3Location || bound.inlineCode !== undefined || bound.image !== undefined ||
      bound.sourceKMSKeyArn !== undefined || bound.s3ObjectStorageMode !== undefined) {
    throw new Error("The reviewed Provider framework must bind its whole S3 ZIP asset.");
  }
  resource.code = {
    s3Bucket: bound.s3Location.bucketName,
    s3Key: bound.s3Location.objectKey,
    ...(bound.s3Location.objectVersion === undefined ? {} :
      { s3ObjectVersion: bound.s3Location.objectVersion }),
  };
  code.bindToResource(resource, { resourceProperty: "Code" });
  if (createHash("sha256").update(readFileSync(artifact)).digest("hex") !==
      IDENTITY_PROVIDER_FRAMEWORK_ZIP_SHA256) {
    throw new Error("The reviewed Provider framework ZIP changed while binding.");
  }
}
