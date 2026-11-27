/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: MIT-0
 */
import { Duration, RemovalPolicy, Stack } from "aws-cdk-lib";
import {
  AllowedMethods,
  CachePolicy,
  Distribution,
  HeadersFrameOption,
  HeadersReferrerPolicy,
  HttpVersion,
  PriceClass,
  ResponseHeadersPolicy,
  SecurityPolicyProtocol,
  ViewerProtocolPolicy,
} from "aws-cdk-lib/aws-cloudfront";
import { S3BucketOrigin } from "aws-cdk-lib/aws-cloudfront-origins";
import {
  BlockPublicAccess,
  Bucket,
  BucketEncryption,
  ObjectOwnership,
} from "aws-cdk-lib/aws-s3";
import { BucketDeployment, ISource, Source } from "aws-cdk-lib/aws-s3-deployment";
import { NagSuppressions } from "cdk-nag";
import { Construct } from "constructs";
import { PortalEnvironment } from "./naming";

export interface PortalWebHostingProps {
  readonly environment: PortalEnvironment;
  /** ARN of the CloudFront-scope web ACL (us-east-1) from the edge stage. */
  readonly webAclArn: string;
  /** Retain the content and log buckets on stack deletion. */
  readonly retainBuckets?: boolean;
}

/**
 * Private Amazon S3 origin behind an Amazon CloudFront distribution with
 * origin access control, a strict response-headers policy and the edge web
 * ACL. The distribution is created first so that sign-in and the API can name
 * its origin; content and `config.json` are published afterwards with
 * {@link PortalWebHosting.publish}.
 */
export class PortalWebHosting extends Construct {
  readonly bucket: Bucket;
  readonly logBucket: Bucket;
  readonly distribution: Distribution;
  /** `https://<distribution domain>` */
  readonly origin: string;

  constructor(scope: Construct, id: string, props: PortalWebHostingProps) {
    super(scope, id);
    if (!/^arn:aws[\w-]*:wafv2:us-east-1:\d{12}:global\/webacl\/.+/.test(props.webAclArn)) {
      throw new Error(
        "Portal web hosting: webAclArn must be a CloudFront-scope (us-east-1, global) web ACL ARN.",
      );
    }
    const retain = props.retainBuckets ?? props.environment === "prod";
    const removalPolicy = retain ? RemovalPolicy.RETAIN : RemovalPolicy.DESTROY;

    this.logBucket = new Bucket(this, "AccessLogs", {
      encryption: BucketEncryption.S3_MANAGED,
      blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      versioned: true,
      // CloudFront standard logging delivers through the bucket ACL.
      objectOwnership: ObjectOwnership.BUCKET_OWNER_PREFERRED,
      lifecycleRules: [{ expiration: Duration.days(365) }],
      removalPolicy,
      autoDeleteObjects: !retain,
    });
    this.bucket = new Bucket(this, "Content", {
      encryption: BucketEncryption.S3_MANAGED,
      blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      versioned: true,
      serverAccessLogsBucket: this.logBucket,
      serverAccessLogsPrefix: "s3/",
      removalPolicy,
      autoDeleteObjects: !retain,
    });

    const headers = new ResponseHeadersPolicy(this, "SecurityHeaders", {
      comment: `Agent Factory Portal (${props.environment}) security headers`,
      securityHeadersBehavior: {
        strictTransportSecurity: {
          accessControlMaxAge: Duration.days(365),
          includeSubdomains: true,
          override: true,
        },
        contentTypeOptions: { override: true },
        frameOptions: { frameOption: HeadersFrameOption.DENY, override: true },
        referrerPolicy: {
          referrerPolicy: HeadersReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN,
          override: true,
        },
        contentSecurityPolicy: {
          // connect-src is https: because the API and the identity provider
          // are separate origins whose host names are deployment values.
          contentSecurityPolicy:
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self' https:; frame-ancestors 'none'; base-uri 'self'; form-action 'self' https:; object-src 'none'",
          override: true,
        },
      },
    });

    this.distribution = new Distribution(this, "Distribution", {
      comment: `Agent Factory Portal (${props.environment})`,
      defaultRootObject: "index.html",
      httpVersion: HttpVersion.HTTP2_AND_3,
      minimumProtocolVersion: SecurityPolicyProtocol.TLS_V1_2_2021,
      priceClass: PriceClass.PRICE_CLASS_100,
      webAclId: props.webAclArn,
      enableLogging: true,
      logBucket: this.logBucket,
      logFilePrefix: "cloudfront/",
      defaultBehavior: {
        origin: S3BucketOrigin.withOriginAccessControl(this.bucket),
        viewerProtocolPolicy: ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        allowedMethods: AllowedMethods.ALLOW_GET_HEAD,
        cachePolicy: CachePolicy.CACHING_OPTIMIZED,
        responseHeadersPolicy: headers,
        compress: true,
      },
      // Client-side routes resolve to the application shell.
      errorResponses: [
        { httpStatus: 403, responseHttpStatus: 200, responsePagePath: "/index.html", ttl: Duration.minutes(1) },
        { httpStatus: 404, responseHttpStatus: 200, responsePagePath: "/index.html", ttl: Duration.minutes(1) },
      ],
    });
    this.origin = `https://${this.distribution.distributionDomainName}`;

    NagSuppressions.addResourceSuppressions(
      this.logBucket,
      [
        {
          id: "AwsSolutions-S1",
          reason: "SEC-041: this is the access-log destination bucket; logging it to itself would recurse.",
        },
        {
          id: "NIST.800.53.R5-S3BucketLoggingEnabled",
          reason: "SEC-041: this is the access-log destination bucket; logging it to itself would recurse.",
        },
        {
          id: "NIST.800.53.R5-S3DefaultEncryptionKMS",
          reason:
            "SEC-003: Amazon CloudFront standard logging and Amazon S3 server access logging deliver only to buckets encrypted with Amazon S3 managed keys.",
        },
        { id: "NIST.800.53.R5-S3BucketReplicationEnabled", reason: "SEC-002: CRR deferred to v2." },
      ],
      true,
    );
    NagSuppressions.addResourceSuppressions(
      this.bucket,
      [
        {
          id: "NIST.800.53.R5-S3DefaultEncryptionKMS",
          reason:
            "SEC-047: the bucket holds only the public static web bundle and a non-secret config.json, both reproducible from source; Amazon S3 managed encryption is sufficient.",
        },
        {
          id: "NIST.800.53.R5-S3BucketReplicationEnabled",
          reason: "SEC-002: content is reproducible from source by redeploying; CRR deferred to v2.",
        },
      ],
      true,
    );
    NagSuppressions.addResourceSuppressions(
      this.distribution,
      [
        {
          id: "AwsSolutions-CFR1",
          reason:
            "SEC-042: the portal is a workforce application reached from the organization's own networks; source restriction is enforced by the edge web ACL allow list, not by country.",
        },
        {
          id: "AwsSolutions-CFR4",
          reason:
            "SEC-043: the distribution uses the default CloudFront certificate, for which CloudFront fixes the viewer security policy; a deployment with its own domain and certificate gets TLS 1.2 (2021) from minimumProtocolVersion.",
        },
      ],
      true,
    );
  }

  /**
   * Publish the built web application and its runtime `config.json`. The
   * deployment invalidates the distribution so a new build is served at once.
   */
  publish(webDistPath: string, config: Record<string, unknown>): BucketDeployment {
    const sources: ISource[] = [
      Source.asset(webDistPath),
      Source.jsonData("config.json", config),
    ];
    const deployment = new BucketDeployment(this, "Publish", {
      sources,
      destinationBucket: this.bucket,
      distribution: this.distribution,
      distributionPaths: ["/index.html", "/config.json"],
      prune: true,
      memoryLimit: 512,
    });
    const stack = Stack.of(this);
    const reasons = [
      {
        id: "AwsSolutions-IAM4",
        reason:
          "SEC-044: the aws-cdk-lib BucketDeployment provider uses AWSLambdaBasicExecutionRole for its own log writes; the construct does not expose the role.",
      },
      {
        id: "AwsSolutions-IAM5",
        reason:
          "SEC-044: the aws-cdk-lib BucketDeployment provider copies the CDK asset objects into the portal content bucket; its object-level wildcards cover those two buckets and the CloudFront invalidation only.",
      },
      { id: "AwsSolutions-L1", reason: "SEC-044: the BucketDeployment provider runtime is fixed by aws-cdk-lib." },
      {
        id: "NIST.800.53.R5-IAMNoInlinePolicy",
        reason: "SEC-044: the BucketDeployment provider role and its inline policy are generated by aws-cdk-lib.",
      },
      {
        id: "NIST.800.53.R5-LambdaConcurrency",
        reason: "SEC-007: the provider runs once per stack deployment, driven by CloudFormation.",
      },
      {
        id: "NIST.800.53.R5-LambdaDLQ",
        reason: "SEC-008: a failed provider run fails the CloudFormation operation, which is the failure signal.",
      },
      {
        id: "NIST.800.53.R5-LambdaInsideVPC",
        reason: "SEC-009: the provider calls Amazon S3 and Amazon CloudFront endpoints only.",
      },
    ];
    for (const child of stack.node.children) {
      if (child.node.id.startsWith("Custom::CDKBucketDeployment")) {
        NagSuppressions.addResourceSuppressions(child, reasons, true);
      }
    }
    NagSuppressions.addResourceSuppressions(deployment, reasons, true);
    return deployment;
  }
}
