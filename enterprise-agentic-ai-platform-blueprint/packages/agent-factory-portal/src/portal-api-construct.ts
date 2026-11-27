/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: MIT-0
 */
import { Aws, Duration, RemovalPolicy, Stack } from "aws-cdk-lib";
import {
  CfnStage,
  CorsHttpMethod,
  HttpApi,
  HttpMethod,
  HttpNoneAuthorizer,
} from "aws-cdk-lib/aws-apigatewayv2";
import { HttpJwtAuthorizer } from "aws-cdk-lib/aws-apigatewayv2-authorizers";
import { HttpLambdaIntegration } from "aws-cdk-lib/aws-apigatewayv2-integrations";
import {
  Effect,
  ManagedPolicy,
  PolicyStatement,
  Role,
  ServicePrincipal,
} from "aws-cdk-lib/aws-iam";
import { IKey } from "aws-cdk-lib/aws-kms";
import {
  Architecture,
  Code,
  Function as LambdaFunction,
  Runtime,
  Tracing,
} from "aws-cdk-lib/aws-lambda";
import { LogGroup, RetentionDays } from "aws-cdk-lib/aws-logs";
import { NagSuppressions } from "cdk-nag";
import { Construct } from "constructs";
import {
  PortalEnvironment,
  PortalIdentityProvider,
  PortalRole,
  portalApiRoleName,
  portalFleetReaderRoleName,
} from "./naming";

/** One Workstream cell the portal reads. */
export interface PortalCell {
  readonly tenantId: string;
  readonly agentId: string;
  readonly applicationId?: string;
  readonly environment: PortalEnvironment;
  readonly accountId: string;
  readonly region: string;
  /**
   * External id configured on the cell's fleet reader role. The role is named
   * for the portal's environment, whatever the cell's own environment is.
   */
  readonly externalId: string;
  /** Prefix of the CloudWatch alarms that belong to the cell. */
  readonly alarmNamePrefix?: string;
  /** Workload pipeline (in the Platform account) that releases the cell. */
  readonly pipelineName?: string;
}

/** Read-only Registry actions of the portal API in the Platform account. */
export const PORTAL_API_REGISTRY_ACTIONS: readonly string[] = [
  "agent-registry:ListRegistryRecords",
  "agent-registry:GetRegistryRecord",
];

/** Read-only release-evidence actions on the named Workload pipelines. */
export const PORTAL_API_PIPELINE_ACTIONS: readonly string[] = [
  "codepipeline:ListPipelineExecutions",
  "codepipeline:ListActionExecutions",
];

/** Read-only Guardrail catalogue actions. */
export const PORTAL_API_GUARDRAIL_ACTIONS: readonly string[] = [
  "bedrock:ListGuardrails",
  "bedrock:GetGuardrail",
  "bedrock:ListTagsForResource",
];

export interface PortalApiProps {
  readonly environment: PortalEnvironment;
  /** Directory holding the built API bundle (handler.py at its root). */
  readonly codePath: string;
  readonly identityProvider: PortalIdentityProvider;
  /** OIDC issuer for the JWT authorizer. */
  readonly jwtIssuer: string;
  /** Accepted token audiences. */
  readonly jwtAudience: readonly string[];
  readonly groupRoleMap: Readonly<Record<string, PortalRole>>;
  readonly registryId: string;
  readonly registryArn: string;
  readonly cells: readonly PortalCell[];
  /** Browser origins allowed to call the API. */
  readonly allowedOrigins: readonly string[];
  /** Approved model catalogue shown by the portal. */
  readonly modelAllowlist?: readonly {
    readonly modelId: string;
    readonly provider: string;
    readonly regions: readonly string[];
    readonly status: string;
  }[];
  /** Tag that marks the Platform's Guardrail profiles. */
  readonly guardrailTag?: { readonly key: string; readonly value: string };
  readonly logRetention?: RetentionDays;
  /**
   * Operator-provisioned customer managed key for the portal's log groups.
   * Its key policy must already allow CloudWatch Logs of this Region. The
   * stack never creates or changes a key (same custody rule as the Omni hub).
   */
  readonly logsKey?: IKey;
}

/**
 * The portal's read-only API: one function behind an Amazon API Gateway HTTP
 * API whose JWT authorizer validates every data request before the function
 * runs. The function reads the Platform Registry with its own role and reads
 * each cell by assuming that cell's fleet reader role.
 */
export class PortalApi extends Construct {
  readonly role: Role;
  readonly handler: LambdaFunction;
  readonly httpApi: HttpApi;
  /** Base URL the web application calls, ending in `/api/v1`. */
  readonly apiBaseUrl: string;

  constructor(scope: Construct, id: string, props: PortalApiProps) {
    super(scope, id);
    const stack = Stack.of(this);
    if (props.allowedOrigins.length === 0) {
      throw new Error("Portal API: at least one allowed origin is required.");
    }
    if (props.jwtAudience.length === 0) {
      throw new Error("Portal API: at least one JWT audience is required.");
    }
    for (const cell of props.cells) {
      if (!/^\d{12}$/.test(cell.accountId)) {
        throw new Error(`Portal API: cell ${cell.tenantId}/${cell.agentId} accountId must be 12 digits.`);
      }
    }

    const handlerLogs = new LogGroup(this, "HandlerLogs", {
      retention: props.logRetention ?? RetentionDays.ONE_YEAR,
      removalPolicy: RemovalPolicy.DESTROY,
      encryptionKey: props.logsKey,
    });
    const accessLogs = new LogGroup(this, "AccessLogs", {
      retention: props.logRetention ?? RetentionDays.ONE_YEAR,
      removalPolicy: RemovalPolicy.DESTROY,
      encryptionKey: props.logsKey,
    });

    this.role = new Role(this, "Role", {
      roleName: portalApiRoleName(props.environment),
      description:
        "Agent Factory Portal API. Read-only: Platform Registry, release evidence, Guardrail catalogue, and the fleet reader role of each Workstream cell.",
      assumedBy: new ServicePrincipal("lambda.amazonaws.com"),
    });
    const policy = new ManagedPolicy(this, "ReadOnly", {
      description: "Agent Factory Portal API: read-only platform data plus its own log and trace writes.",
      roles: [this.role],
    });
    policy.addStatements(
      new PolicyStatement({
        sid: "PortalWriteOwnLogs",
        effect: Effect.ALLOW,
        actions: ["logs:CreateLogStream", "logs:PutLogEvents"],
        resources: [handlerLogs.logGroupArn, `${handlerLogs.logGroupArn}:*`],
      }),
    );
    policy.addStatements(
      new PolicyStatement({
        sid: "PortalTracing",
        effect: Effect.ALLOW,
        actions: ["xray:PutTraceSegments", "xray:PutTelemetryRecords"],
        resources: ["*"],
      }),
    );
    policy.addStatements(
      new PolicyStatement({
        sid: "PortalReadRegistry",
        effect: Effect.ALLOW,
        actions: [...PORTAL_API_REGISTRY_ACTIONS],
        resources: [props.registryArn, `${props.registryArn}/record/*`],
      }),
    );
    policy.addStatements(
      new PolicyStatement({
        sid: "PortalListGuardrails",
        effect: Effect.ALLOW,
        actions: ["bedrock:ListGuardrails"],
        resources: ["*"],
        conditions: { StringEquals: { "aws:RequestedRegion": stack.region } },
      }),
    );
    policy.addStatements(
      new PolicyStatement({
        sid: "PortalReadGuardrails",
        effect: Effect.ALLOW,
        actions: ["bedrock:GetGuardrail", "bedrock:ListTagsForResource"],
        resources: [
          `arn:${Aws.PARTITION}:bedrock:${stack.region}:${stack.account}:guardrail/*`,
        ],
      }),
    );
    const pipelineNames = [
      ...new Set(props.cells.map((c) => c.pipelineName).filter((n): n is string => !!n)),
    ];
    if (pipelineNames.length > 0) {
      policy.addStatements(
        new PolicyStatement({
          sid: "PortalReadReleaseEvidence",
          effect: Effect.ALLOW,
          actions: [...PORTAL_API_PIPELINE_ACTIONS],
          resources: pipelineNames.map(
            (name) =>
              `arn:${Aws.PARTITION}:codepipeline:${stack.region}:${stack.account}:${name}`,
          ),
        }),
      );
    }
    const readerRoleArns = [
      ...new Set(
        props.cells.map(
          (c) =>
            `arn:${Aws.PARTITION}:iam::${c.accountId}:role/${portalFleetReaderRoleName(props.environment)}`,
        ),
      ),
    ];
    if (readerRoleArns.length > 0) {
      policy.addStatements(
        new PolicyStatement({
          sid: "PortalAssumeFleetReader",
          effect: Effect.ALLOW,
          actions: ["sts:AssumeRole"],
          resources: readerRoleArns,
        }),
      );
    }

    const cellsEnv = props.cells.map((c) => ({
      tenantId: c.tenantId,
      agentId: c.agentId,
      applicationId: c.applicationId,
      environment: c.environment,
      accountId: c.accountId,
      region: c.region,
      readerRoleArn: `arn:${Aws.PARTITION}:iam::${c.accountId}:role/${portalFleetReaderRoleName(props.environment)}`,
      externalId: c.externalId,
      alarmNamePrefix: c.alarmNamePrefix,
      pipelineName: c.pipelineName,
    }));

    // The function must not start before its permissions exist.
    this.handler = new LambdaFunction(this, "Handler", {
      description: "Agent Factory Portal read-only API.",
      runtime: Runtime.PYTHON_3_13,
      architecture: Architecture.ARM_64,
      handler: "handler.handler",
      code: Code.fromAsset(props.codePath),
      // Permissions come only from the managed policy above; the function
      // construct must not add an inline policy to the role.
      role: this.role.withoutPolicyUpdates(),
      memorySize: 1024,
      timeout: Duration.seconds(29),
      reservedConcurrentExecutions: 20,
      tracing: Tracing.ACTIVE,
      logGroup: handlerLogs,
      environment: {
        PORTAL_ENV: props.environment,
        PORTAL_REGISTRY_ID: props.registryId,
        PORTAL_REGISTRY_REGION: stack.region,
        PORTAL_CELLS: stack.toJsonString(cellsEnv),
        PORTAL_IDENTITY_PROVIDER: props.identityProvider,
        PORTAL_GROUP_ROLE_MAP: JSON.stringify(props.groupRoleMap),
        PORTAL_GUARDRAIL_TAG_KEY: props.guardrailTag?.key ?? "",
        PORTAL_GUARDRAIL_TAG_VALUE: props.guardrailTag?.value ?? "",
        PORTAL_MODEL_ALLOWLIST: JSON.stringify(
          (props.modelAllowlist ?? []).map((m) => ({
            model_id: m.modelId,
            provider: m.provider,
            regions: m.regions,
            status: m.status,
          })),
        ),
        PORTAL_ALLOWED_ORIGINS: stack.toJsonString(props.allowedOrigins),
        PORTAL_CACHE_TTL_SECONDS: "30",
      },
    });

    this.httpApi = new HttpApi(this, "HttpApi", {
      apiName: `agenticai-portal-${props.environment}`,
      description: "Agent Factory Portal read-only API.",
      createDefaultStage: true,
      corsPreflight: {
        allowOrigins: [...props.allowedOrigins],
        allowMethods: [CorsHttpMethod.GET, CorsHttpMethod.OPTIONS],
        allowHeaders: ["authorization", "content-type"],
        maxAge: Duration.minutes(10),
      },
    });
    const integration = new HttpLambdaIntegration("PortalIntegration", this.handler);
    const authorizer = new HttpJwtAuthorizer("PortalJwt", props.jwtIssuer, {
      jwtAudience: [...props.jwtAudience],
      identitySource: ["$request.header.Authorization"],
    });
    // M1 is read-only: only GET routes exist, so any other method has no route.
    this.httpApi.addRoutes({
      path: "/api/v1/{proxy+}",
      methods: [HttpMethod.GET],
      integration,
      authorizer,
    });
    const healthRoutes = this.httpApi.addRoutes({
      path: "/api/v1/health",
      methods: [HttpMethod.GET],
      integration,
      authorizer: new HttpNoneAuthorizer(),
    });

    const stage = this.httpApi.defaultStage?.node.defaultChild as CfnStage;
    stage.accessLogSettings = {
      destinationArn: accessLogs.logGroupArn,
      format: JSON.stringify({
        requestId: "$context.requestId",
        requestTime: "$context.requestTime",
        routeKey: "$context.routeKey",
        status: "$context.status",
        sourceIp: "$context.identity.sourceIp",
        subject: "$context.authorizer.claims.sub",
        authorizerError: "$context.authorizer.error",
        integrationError: "$context.integrationErrorMessage",
        responseLength: "$context.responseLength",
      }),
    };
    stage.defaultRouteSettings = {
      throttlingBurstLimit: 50,
      throttlingRateLimit: 25,
      detailedMetricsEnabled: true,
    };
    accessLogs.grantWrite(new ServicePrincipal("apigateway.amazonaws.com"));

    this.apiBaseUrl = `${this.httpApi.apiEndpoint}/api/v1`;

    this.handler.node.addDependency(policy);
    NagSuppressions.addResourceSuppressions(
      policy,
      [
        {
          id: "AwsSolutions-IAM5",
          reason:
            "SEC-039: X-Ray segment writes have no resource type; Registry records and Guardrail profiles are created by the Platform pipeline after synthesis, so reads are scoped to the one Registry's records and to this account's Guardrails; log writes are scoped to the function's own log group streams. The policy holds no mutating action other than the function's own log and trace writes.",
        },
      ],
      true,
    );
    NagSuppressions.addResourceSuppressions(
      this.handler,
      [
        {
          id: "AwsSolutions-L1",
          reason:
            "SEC-045: Python 3.13 is the runtime the blueprint's functions are built and tested on; the portal bundle is built for it.",
        },
        {
          id: "NIST.800.53.R5-LambdaDLQ",
          reason:
            "SEC-008: the function is invoked synchronously by API Gateway only; a dead-letter queue applies to asynchronous invocation and would never receive an event.",
        },
        {
          id: "NIST.800.53.R5-LambdaInsideVPC",
          reason:
            "SEC-009: the function calls AWS service endpoints only (Registry, AgentCore, CloudWatch, CodePipeline, STS) and reaches no VPC resource.",
        },
      ],
      true,
    );
    if (!props.logsKey) {
      NagSuppressions.addResourceSuppressions(
        [handlerLogs, accessLogs],
        [
          {
            id: "NIST.800.53.R5-CloudWatchLogGroupEncrypted",
            reason:
              "SEC-046: CloudWatch Logs encrypts log data at rest by default. A customer managed key is supplied by operators through agenticai/portalLogsKeyArn; the portal stack does not create or tag keys, so its execution role needs no key administration.",
          },
        ],
        true,
      );
    }
    NagSuppressions.addResourceSuppressions(
      healthRoutes,
      [
        {
          id: "AwsSolutions-APIG4",
          reason:
            "SEC-040: the liveness route returns no data and must be callable before sign-in; every data route uses the JWT authorizer.",
        },
      ],
      true,
    );
  }
}
