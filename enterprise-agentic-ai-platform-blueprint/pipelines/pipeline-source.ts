import { S3Trigger } from "aws-cdk-lib/aws-codepipeline-actions";
import { Bucket } from "aws-cdk-lib/aws-s3";
import { CodePipelineSource } from "aws-cdk-lib/pipelines";
import { Construct } from "constructs";

export interface PipelineSourceProps {
  readonly githubRepo?: string;
  readonly githubBranch?: string;
  readonly githubConnectionArn?: string;
  /** Versioned, private source bucket. Use a digest-specific archive key. */
  readonly s3Source?: {
    readonly bucketName: string;
    readonly objectKey: string;
  };
}

/** GitHub mainline remains the default; S3 supports frozen local test sources. */
export function createPipelineSource(
  scope: Construct,
  props: PipelineSourceProps,
): CodePipelineSource {
  if (props.s3Source) {
    const { bucketName, objectKey } = props.s3Source;
    if (
      !/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(bucketName) ||
      !objectKey.trim() ||
      objectKey.startsWith("/") ||
      objectKey.split("/").includes("..")
    ) {
      throw new Error("Pipeline S3 source requires a bucket name and relative object key.");
    }
    return CodePipelineSource.s3(
      Bucket.fromBucketName(scope, "FrozenSourceBucket", bucketName),
      objectKey,
      { trigger: S3Trigger.NONE, actionName: "FrozenSource" },
    );
  }
  if (!props.githubRepo?.trim() || !props.githubConnectionArn?.trim()) {
    throw new Error("Pipeline source requires GitHub repository/connection or an S3 archive.");
  }
  return CodePipelineSource.connection(
    props.githubRepo,
    props.githubBranch ?? "main",
    { connectionArn: props.githubConnectionArn },
  );
}

/** Carry the selected source through self-mutation without switching to mainline. */
export function pipelineSourceContext(
  props: PipelineSourceProps,
): Record<string, string> {
  if (props.s3Source) {
    return {
      "agenticai/sourceBucketName": props.s3Source.bucketName,
      "agenticai/sourceObjectKey": props.s3Source.objectKey,
    };
  }
  return {
    "agenticai/githubRepo": props.githubRepo ?? "",
    "agenticai/githubConnectionArn": props.githubConnectionArn ?? "",
    "agenticai/githubBranch": props.githubBranch ?? "main",
  };
}
