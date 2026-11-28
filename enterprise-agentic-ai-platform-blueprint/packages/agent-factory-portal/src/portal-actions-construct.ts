/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: MIT-0
 */
import { Aws, Duration, RemovalPolicy, Stack } from "aws-cdk-lib";
import { HttpApi, HttpMethod, IHttpRouteAuthorizer } from "aws-cdk-lib/aws-apigatewayv2";
import { HttpLambdaIntegration } from "aws-cdk-lib/aws-apigatewayv2-integrations";
import { Alarm, ComparisonOperator, TreatMissingData } from "aws-cdk-lib/aws-cloudwatch";
import { SnsAction } from "aws-cdk-lib/aws-cloudwatch-actions";
import { AttributeType, BillingMode, Table, TableEncryption } from "aws-cdk-lib/aws-dynamodb";
import { AnyPrincipal, Effect, ManagedPolicy, PolicyStatement, Role, ServicePrincipal } from "aws-cdk-lib/aws-iam";
import { IKey } from "aws-cdk-lib/aws-kms";
import { Architecture, Code, Function as LambdaFunction, Runtime, Tracing } from "aws-cdk-lib/aws-lambda";
import { SqsEventSource } from "aws-cdk-lib/aws-lambda-event-sources";
import { LogGroup, RetentionDays } from "aws-cdk-lib/aws-logs";
import { Topic } from "aws-cdk-lib/aws-sns";
import { Queue, QueueEncryption } from "aws-cdk-lib/aws-sqs";
import { NagSuppressions } from "cdk-nag";
import { Construct } from "constructs";
import {
  PortalEnvironment,
  PortalRole,
  portalContainmentRoleName,
  portalContainmentTargetRoleName,
} from "./naming";
import { PortalCell, PortalRouteThrottle, portalCellsEnvironment, throttlePortalRoute } from "./portal-api-construct";

/**
 * Registry actions of the registrar function. It can create, change, submit
 * and delete records; it cannot decide a record's approval status.
 */
export const PORTAL_REGISTRAR_REGISTRY_ACTIONS: readonly string[] = [
  "agent-registry:CreateRegistryRecord",
  "agent-registry:UpdateRegistryRecord",
  "agent-registry:SubmitRegistryRecordForApproval",
  "agent-registry:DeleteRegistryRecord",
  "agent-registry:GetRegistryRecord",
  "agent-registry:ListRegistryRecords",
];

/**
 * Registry actions of the approver function. It can decide a record's status
 * and read the record; it cannot create or change one.
 */
export const PORTAL_APPROVER_REGISTRY_ACTIONS: readonly string[] = [
  "agent-registry:UpdateRegistryRecordStatus",
  "agent-registry:GetRegistryRecord",
];

/**
 * The audit trail is append-only. The registrar only appends; the approver
 * appends and reads (it must find a record's submitter to refuse a
 * self-approval); the read API only reads. Nothing can rewrite or delete.
 */
export const PORTAL_REGISTRAR_AUDIT_ACTIONS: readonly string[] = ["dynamodb:PutItem"];
export const PORTAL_APPROVER_AUDIT_ACTIONS: readonly string[] = ["dynamodb:PutItem", "dynamodb:Query"];
/**
 * The partitions of the audit table each function may touch, as leading-key
 * patterns. The history of a registration is under `RECORD#...`, the review
 * attestations under `REVIEWS`, and the containment history of a Runtime under
 * `CONTAINMENT#<Runtime ARN>`. A function cannot write an entry of another
 * kind: the registrar cannot attest a review, and neither registration
 * function can write into a containment history or the reverse.
 */
export const PORTAL_REGISTRAR_AUDIT_KEYS: readonly string[] = ["RECORD#*"];
export const PORTAL_APPROVER_AUDIT_KEYS: readonly string[] = ["RECORD#*", "REVIEWS"];
export const PORTAL_CONTAINMENT_AUDIT_KEYS: readonly string[] = ["CONTAINMENT#*"];
/**
 * What only the containment role may do with a message of the sweep queue.
 * Sending starts a sweep; receiving, deleting, purging or hiding a message
 * would make a scheduled sweep disappear without a trace.
 */
export const PORTAL_SWEEP_MESSAGE_ACTIONS: readonly string[] = [
  "sqs:SendMessage",
  "sqs:ReceiveMessage",
  "sqs:DeleteMessage",
  "sqs:ChangeMessageVisibility",
  "sqs:PurgeQueue",
];
/** Contain and release are emergency actions: each has a request budget no other route can use up. */
export const PORTAL_CONTAINMENT_ROUTE_THROTTLE: PortalRouteThrottle = { rateLimit: 5, burstLimit: 10 };
/** A sweep waits at most 15 minutes and runs at most 15; one that is an hour old is not being processed. */
export const PORTAL_SWEEP_BACKLOG_SECONDS = 3600;
/**
 * The containment function reads one record of the agent Registry, to resolve
 * a registered agent's Runtime and tenant. It cannot create, change, submit,
 * approve or delete a record.
 */
export const PORTAL_CONTAINMENT_REGISTRY_ACTIONS: readonly string[] = ["agent-registry:GetRegistryRecord"];
/**
 * What the containment role does with the queue of background sweeps: the
 * containment function sends, the sweeper function receives and deletes.
 */
export const PORTAL_SWEEP_QUEUE_ACTIONS: readonly string[] = [
  "sqs:SendMessage",
  "sqs:ReceiveMessage",
  "sqs:DeleteMessage",
  "sqs:GetQueueAttributes",
];
/** A sweep pages through every session of the lookback window; this is the function's own limit. */
export const PORTAL_SWEEPER_TIMEOUT = Duration.seconds(900);
export const PORTAL_AUDIT_READER_ACTIONS: readonly string[] = ["dynamodb:Query"];

export function portalRegistrarRoleName(environment: PortalEnvironment): string {
  return `AgenticAI-RegistryRegistrar-${environment}`;
}

export function portalApproverRoleName(environment: PortalEnvironment): string {
  return `AgenticAI-RegistryApprover-${environment}`;
}

export interface PortalAuditTrailProps {
  readonly environment: PortalEnvironment;
  readonly retain?: boolean;
}

/** Append-only record of every registration decision, allowed or denied. */
export class PortalAuditTrail extends Construct {
  readonly table: Table;

  constructor(scope: Construct, id: string, props: PortalAuditTrailProps) {
    super(scope, id);
    const retain = props.retain ?? props.environment === "prod";
    this.table = new Table(this, "Table", {
      partitionKey: { name: "pk", type: AttributeType.STRING },
      sortKey: { name: "sk", type: AttributeType.STRING },
      billingMode: BillingMode.PAY_PER_REQUEST,
      // Encrypted at rest with an AWS owned key: the stack's execution role
      // then needs no KMS permission (see portal-api-construct on key custody).
      encryption: TableEncryption.DEFAULT,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      deletionProtection: retain,
      removalPolicy: retain ? RemovalPolicy.RETAIN : RemovalPolicy.DESTROY,
    });
    NagSuppressions.addResourceSuppressions(
      this.table,
      [
        {
          id: "NIST.800.53.R5-DynamoDBInBackupPlan",
          reason:
            "SEC-048: the audit trail is protected by point-in-time recovery; enrolling it in an AWS Backup plan is the adopter's organization-wide backup policy, not a stack resource.",
        },
      ],
      true,
    );
  }
}

export interface PortalActionsProps {
  readonly environment: PortalEnvironment;
  /** Directory holding the built API bundle (same bundle as the read API). */
  readonly codePath: string;
  readonly httpApi: HttpApi;
  readonly authorizer: IHttpRouteAuthorizer;
  readonly registryId: string;
  readonly registryArn: string;
  readonly auditTable: Table;
  readonly identityProvider: string;
  /**
   * The issuer and audiences of the sign-in tokens, the same values the API's
   * JWT authorizer checks. The action functions verify the bearer token
   * themselves with them, so that an event handed to a function directly,
   * with claims of the caller's own making, carries no weight.
   */
  readonly jwtIssuer: string;
  readonly jwtAudience: readonly string[];
  /** Where the issuer publishes its signing keys, when it cannot be derived from the issuer. */
  readonly jwksUrl?: string;
  readonly groupRoleMap: Readonly<Record<string, PortalRole>>;
  /** Group or app-role name to the tenant ids its members may register for. */
  readonly groupTenantMap: Readonly<Record<string, readonly string[]>>;
  readonly allowedOrigins: readonly string[];
  readonly logRetention?: RetentionDays;
  readonly logsKey?: IKey;
  /** Cells; those with `containment` set can be contained from the portal. */
  readonly cells?: readonly PortalCell[];
  /**
   * An operator-provisioned Amazon SNS topic that is told when a background
   * containment sweep could not be processed. Without it the alarm exists and
   * notifies nobody.
   */
  readonly alarmTopicArn?: string;
}

interface ActionFunctionSpec {
  readonly id: string;
  readonly actionRole: "registrar" | "approver" | "containment";
  readonly roleName: string;
  readonly handler: string;
  /** Registry actions on the agent Registry, when the function writes records. */
  readonly registryActions?: readonly string[];
  readonly auditActions: readonly string[];
  /** Leading-key patterns of the audit table partitions this function may read or write. */
  readonly auditKeys: readonly string[];
  /** Extra statements of this function only. */
  readonly statements?: PolicyStatement[];
  readonly environment?: Record<string, string>;
  /** Reserved concurrency. Defaults to 5. */
  readonly reservedConcurrency?: number;
  readonly description: string;
}

/**
 * Governed registration and approval. Two functions with two roles, so that
 * separation of duties holds in IAM as well as in the authorization core:
 * the registrar function cannot decide an approval, and the approver function
 * cannot create or change a record. Both append to the audit trail and
 * neither can rewrite it.
 */
export class PortalActions extends Construct {
  readonly registrarRole: Role;
  readonly approverRole: Role;
  /** Present when at least one cell has deployed the containment target role. */
  readonly containmentRole?: Role;
  /** The queue of background containment sweeps; present with `containmentRole`. */
  readonly sweepQueue?: Queue;

  constructor(scope: Construct, id: string, props: PortalActionsProps) {
    super(scope, id);
    const stack = Stack.of(this);
    const recordsArn = `${props.registryArn}/record/*`;
    const cellsEnvironment = stack.toJsonString(
      portalCellsEnvironment(props.cells ?? [], props.environment, Aws.PARTITION),
    );

    const build = (spec: ActionFunctionSpec): { role: Role; fn: LambdaFunction; policy: ManagedPolicy } => {
      const logs = new LogGroup(this, `${spec.id}Logs`, {
        retention: props.logRetention ?? RetentionDays.ONE_YEAR,
        removalPolicy: RemovalPolicy.DESTROY,
        encryptionKey: props.logsKey,
      });
      const role = new Role(this, `${spec.id}Role`, {
        roleName: spec.roleName,
        description: spec.description,
        assumedBy: new ServicePrincipal("lambda.amazonaws.com"),
      });
      const policy = new ManagedPolicy(this, `${spec.id}Policy`, {
        description: spec.description,
        roles: [role],
        statements: [
          new PolicyStatement({
            sid: "WriteOwnLogs",
            effect: Effect.ALLOW,
            actions: ["logs:CreateLogStream", "logs:PutLogEvents"],
            resources: [logs.logGroupArn, `${logs.logGroupArn}:*`],
          }),
          new PolicyStatement({
            sid: "Tracing",
            effect: Effect.ALLOW,
            actions: ["xray:PutTraceSegments", "xray:PutTelemetryRecords"],
            resources: ["*"],
          }),
          ...(spec.registryActions
            ? [
                new PolicyStatement({
                  sid: "RegistryRecords",
                  effect: Effect.ALLOW,
                  actions: [...spec.registryActions],
                  resources: [props.registryArn, recordsArn],
                }),
              ]
            : []),
          ...(spec.statements ?? []),
          new PolicyStatement({
            sid: "AuditTrail",
            effect: Effect.ALLOW,
            actions: [...spec.auditActions],
            resources: [props.auditTable.tableArn],
            conditions: { "ForAllValues:StringLike": { "dynamodb:LeadingKeys": [...spec.auditKeys] } },
          }),
        ],
      });
      const fn = new LambdaFunction(this, `${spec.id}Function`, {
        description: spec.description,
        runtime: Runtime.PYTHON_3_13,
        architecture: Architecture.ARM_64,
        handler: spec.handler,
        code: Code.fromAsset(props.codePath),
        role: role.withoutPolicyUpdates(),
        memorySize: 512,
        timeout: Duration.seconds(29),
        reservedConcurrentExecutions: spec.reservedConcurrency ?? 5,
        tracing: Tracing.ACTIVE,
        logGroup: logs,
        environment: {
          PORTAL_ENV: props.environment,
          PORTAL_ACTION_ROLE: spec.actionRole,
          PORTAL_REGISTRY_ID: props.registryId,
          PORTAL_REGISTRY_REGION: stack.region,
          PORTAL_AUDIT_TABLE: props.auditTable.tableName,
          PORTAL_IDENTITY_PROVIDER: props.identityProvider,
          PORTAL_JWT_ISSUER: props.jwtIssuer,
          PORTAL_JWT_AUDIENCE: stack.toJsonString(props.jwtAudience),
          ...(props.jwksUrl ? { PORTAL_JWKS_URL: props.jwksUrl } : {}),
          PORTAL_GROUP_ROLE_MAP: JSON.stringify(props.groupRoleMap),
          PORTAL_GROUP_TENANT_MAP: JSON.stringify(props.groupTenantMap),
          PORTAL_ALLOWED_ORIGINS: stack.toJsonString(props.allowedOrigins),
          // Configuration only: the registrar and the approver check that a registration's
          // Runtime runs in a cell of the registration's own tenant.
          PORTAL_CELLS: cellsEnvironment,
          ...(spec.environment ?? {}),
        },
      });
      fn.node.addDependency(policy);
      NagSuppressions.addResourceSuppressions(
        policy,
        [
          {
            id: "AwsSolutions-IAM5",
            reason:
              "SEC-049: X-Ray segment writes have no resource type; Registry records are created at run time, so the statement is scoped to the records of the one Registry; log writes are scoped to the function's own log group streams.",
          },
        ],
        true,
      );
      NagSuppressions.addResourceSuppressions(
        fn,
        [
          {
            id: "AwsSolutions-L1",
            reason: "SEC-045: Python 3.13 is the runtime the blueprint's functions are built and tested on.",
          },
          {
            id: "NIST.800.53.R5-LambdaDLQ",
            reason: "SEC-008: invoked synchronously by API Gateway only; the caller receives the failure.",
          },
          {
            id: "NIST.800.53.R5-LambdaInsideVPC",
            reason: "SEC-009: calls AWS service endpoints only (Registry, DynamoDB) and reaches no VPC resource.",
          },
        ],
        true,
      );
      if (!props.logsKey) {
        NagSuppressions.addResourceSuppressions(
          logs,
          [
            {
              id: "NIST.800.53.R5-CloudWatchLogGroupEncrypted",
              reason:
                "SEC-046: CloudWatch Logs encrypts log data at rest by default; a customer managed key is supplied by operators through agenticai/portalLogsKeyArn.",
            },
          ],
          true,
        );
      }
      return { role, fn, policy };
    };

    const registrar = build({
      id: "Registrar",
      actionRole: "registrar",
      roleName: portalRegistrarRoleName(props.environment),
      handler: "registrar_handler.handler",
      registryActions: PORTAL_REGISTRAR_REGISTRY_ACTIONS,
      auditActions: PORTAL_REGISTRAR_AUDIT_ACTIONS,
      auditKeys: PORTAL_REGISTRAR_AUDIT_KEYS,
      description:
        "Agent Factory Portal registrar: creates, updates, submits and deletes agent governance records. Cannot approve.",
    });
    const approver = build({
      id: "Approver",
      actionRole: "approver",
      roleName: portalApproverRoleName(props.environment),
      handler: "approver_handler.handler",
      registryActions: PORTAL_APPROVER_REGISTRY_ACTIONS,
      auditActions: PORTAL_APPROVER_AUDIT_ACTIONS,
      auditKeys: PORTAL_APPROVER_AUDIT_KEYS,
      description:
        "Agent Factory Portal approver: approves or rejects a submitted agent governance record. Cannot create or change one.",
    });
    this.registrarRole = registrar.role;
    this.approverRole = approver.role;

    // Incident containment: its own function and role. The role can only
    // assume the containment target role of cells that deployed one, read one
    // record of the agent Registry (to resolve a registered agent's Runtime
    // and tenant), and append to and read the audit trail. It holds no
    // AgentCore permission of its own and cannot change a Registry record.
    const containmentCells = (props.cells ?? []).filter((c) => c.containment);
    if (containmentCells.length > 0) {
      const targets = [
        ...new Set(
          containmentCells.map(
            (c) =>
              `arn:${Aws.PARTITION}:iam::${c.accountId}:role/${portalContainmentTargetRoleName(props.environment)}`,
          ),
        ),
      ];
      // Containment finishes in the background. The containment function answers once the deny
      // statement is verified, and leaves messages on this queue: a sweep now when the first one
      // was cut short, and later sweeps (message timers) that catch a session which started on a
      // host that had not yet applied the deny. A sweeper function consumes them.
      const sweepDeadLetters = new Queue(this, "SweepDeadLetters", {
        encryption: QueueEncryption.SQS_MANAGED,
        enforceSSL: true,
        retentionPeriod: Duration.days(14),
      });
      const sweepQueue = new Queue(this, "SweepQueue", {
        encryption: QueueEncryption.SQS_MANAGED,
        enforceSSL: true,
        // One times the sweeper's timeout: a sweep retried much later says nothing useful, and
        // the sweeper records its own failures, so a redelivery only follows a crash or a timeout.
        visibilityTimeout: PORTAL_SWEEPER_TIMEOUT,
        // The last sweep is delayed 15 minutes and can be received twice, 15 minutes apart, before
        // it is set aside: about 45 minutes. A message that outlives its retention is deleted
        // without reaching the dead-letter queue, so the retention leaves room for a throttled
        // sweeper and the failure still ends in the alarm.
        retentionPeriod: Duration.hours(4),
        deadLetterQueue: { queue: sweepDeadLetters, maxReceiveCount: 2 },
      });
      const containment = build({
        id: "Containment",
        actionRole: "containment",
        roleName: portalContainmentRoleName(props.environment),
        handler: "containment_handler.handler",
        // A contain can hold a slot for most of its timeout while it stops sessions. Refused
        // requests are cheap (nothing is looked up or written), but they share the same slots,
        // so this function gets more of them than the registration functions.
        reservedConcurrency: 20,
        registryActions: PORTAL_CONTAINMENT_REGISTRY_ACTIONS,
        auditActions: PORTAL_APPROVER_AUDIT_ACTIONS,
        auditKeys: PORTAL_CONTAINMENT_AUDIT_KEYS,
        statements: [
          new PolicyStatement({
            sid: "AssumeCellContainmentTarget",
            effect: Effect.ALLOW,
            actions: ["sts:AssumeRole"],
            resources: targets,
          }),
          // The containment function sends; the sweeper, which runs with this same role so that
          // no cell has to trust a second principal, receives and deletes.
          new PolicyStatement({
            sid: "SweepQueue",
            effect: Effect.ALLOW,
            actions: [...PORTAL_SWEEP_QUEUE_ACTIONS],
            resources: [sweepQueue.queueArn],
          }),
        ],
        environment: {
          PORTAL_SWEEP_QUEUE_URL: sweepQueue.queueUrl,
        },
        description:
          "Agent Factory Portal containment: blocks and unblocks invocation of a Runtime and stops its sessions, through the containment target role of the agent's cell. Cannot invoke, change or delete anything.",
      });
      this.containmentRole = containment.role;
      // Only the containment role handles the messages of the queue: the containment function
      // sends them and the sweeper, which runs with the same role, receives and deletes them.
      // The sweeper treats every message as untrusted input anyway; this keeps any other
      // principal of the account, however broad its own permissions, from starting a sweep or
      // from making a scheduled one disappear.
      sweepQueue.addToResourcePolicy(
        new PolicyStatement({
          sid: "OnlyTheContainmentRoleHandlesMessages",
          effect: Effect.DENY,
          principals: [new AnyPrincipal()],
          actions: [...PORTAL_SWEEP_MESSAGE_ACTIONS],
          resources: [sweepQueue.queueArn],
          conditions: { ArnNotEquals: { "aws:PrincipalArn": containment.role.roleArn } },
        }),
      );

      const sweeperLogs = new LogGroup(this, "SweeperLogs", {
        retention: props.logRetention ?? RetentionDays.ONE_YEAR,
        removalPolicy: RemovalPolicy.DESTROY,
        encryptionKey: props.logsKey,
      });
      containment.policy.addStatements(
        new PolicyStatement({
          sid: "WriteSweeperLogs",
          effect: Effect.ALLOW,
          actions: ["logs:CreateLogStream", "logs:PutLogEvents"],
          resources: [sweeperLogs.logGroupArn, `${sweeperLogs.logGroupArn}:*`],
        }),
      );
      const sweeper = new LambdaFunction(this, "SweeperFunction", {
        description:
          "Agent Factory Portal containment sweeper: stops the sessions of a contained Runtime in the background and records each sweep. Reached only through its queue; it has no route.",
        runtime: Runtime.PYTHON_3_13,
        architecture: Architecture.ARM_64,
        handler: "sweep_handler.handler",
        code: Code.fromAsset(props.codePath),
        role: containment.role.withoutPolicyUpdates(),
        memorySize: 512,
        timeout: PORTAL_SWEEPER_TIMEOUT,
        reservedConcurrentExecutions: 2,
        tracing: Tracing.ACTIVE,
        logGroup: sweeperLogs,
        environment: {
          PORTAL_ENV: props.environment,
          PORTAL_ACTION_ROLE: "sweeper",
          PORTAL_REGISTRY_REGION: stack.region,
          PORTAL_AUDIT_TABLE: props.auditTable.tableName,
          PORTAL_CELLS: cellsEnvironment,
        },
      });
      sweeper.node.addDependency(containment.policy);
      sweeper.addEventSource(new SqsEventSource(sweepQueue, { batchSize: 1, maxConcurrency: 2 }));
      const stuckSweeps = new Alarm(this, "SweepDeadLettersAlarm", {
        alarmDescription:
          "A background containment sweep of the Agent Factory Portal could not be processed twice and was set aside. Sessions of a contained agent may still be running: contain it again, and look at the sweeper's log.",
        metric: sweepDeadLetters.metricApproximateNumberOfMessagesVisible({ period: Duration.minutes(1) }),
        threshold: 1,
        evaluationPeriods: 1,
        comparisonOperator: ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        treatMissingData: TreatMissingData.NOT_BREACHING,
      });
      // A sweep that waits is not in the dead-letter queue, and one that outlives the queue's
      // retention is discarded without ever reaching it. So the wait itself is watched.
      const waitingSweeps = new Alarm(this, "SweepBacklogAlarm", {
        alarmDescription:
          "Background containment sweeps of the Agent Factory Portal have been waiting for more than an hour: the sweeper is failing or not keeping up. A sweep that waits four hours is discarded. Look at the sweeper's log and its concurrency.",
        metric: sweepQueue.metricApproximateAgeOfOldestMessage({ period: Duration.minutes(5) }),
        threshold: PORTAL_SWEEP_BACKLOG_SECONDS,
        evaluationPeriods: 1,
        comparisonOperator: ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        treatMissingData: TreatMissingData.NOT_BREACHING,
      });
      if (props.alarmTopicArn) {
        const topic = Topic.fromTopicArn(this, "AlarmTopic", props.alarmTopicArn);
        stuckSweeps.addAlarmAction(new SnsAction(topic));
        waitingSweeps.addAlarmAction(new SnsAction(topic));
      }
      NagSuppressions.addResourceSuppressions(
        sweeper,
        [
          {
            id: "AwsSolutions-L1",
            reason: "SEC-045: Python 3.13 is the runtime the blueprint's functions are built and tested on.",
          },
          {
            id: "NIST.800.53.R5-LambdaDLQ",
            reason:
              "SEC-051: invoked only from its queue, which redrives a message that failed twice to a dead-letter queue with an alarm; a function-level dead-letter target applies to asynchronous invocation, which this function does not receive.",
          },
          {
            id: "NIST.800.53.R5-LambdaInsideVPC",
            reason: "SEC-009: calls AWS service endpoints only (STS, AgentCore, CloudWatch Logs, DynamoDB) and reaches no VPC resource.",
          },
        ],
        true,
      );
      if (!props.logsKey) {
        NagSuppressions.addResourceSuppressions(
          sweeperLogs,
          [
            {
              id: "NIST.800.53.R5-CloudWatchLogGroupEncrypted",
              reason:
                "SEC-046: CloudWatch Logs encrypts log data at rest by default; a customer managed key is supplied by operators through agenticai/portalLogsKeyArn.",
            },
          ],
          true,
        );
      }
      for (const alarm of props.alarmTopicArn ? [] : [stuckSweeps, waitingSweeps]) {
        NagSuppressions.addResourceSuppressions(
          alarm,
          [
            {
              id: "NIST.800.53.R5-CloudWatchAlarmAction",
              reason:
                "SEC-052: the notification topic is operator-provisioned and passed through agenticai/portalAlarmTopicArn, like the log keys; the stack creates no topic and no subscription. Without it the alarm state is still recorded and visible.",
            },
          ],
          true,
        );
      }
      this.sweepQueue = sweepQueue;
      const containmentIntegration = new HttpLambdaIntegration("PortalContainment", containment.fn);
      for (const action of ["contain", "release"]) {
        const routes = props.httpApi.addRoutes({
          path: `/api/v1/agents/{agent_id}/containment/${action}`,
          methods: [HttpMethod.POST],
          integration: containmentIntegration,
          authorizer: props.authorizer,
        });
        // An emergency action must not be throttled by traffic on the other routes.
        throttlePortalRoute(props.httpApi, routes, PORTAL_CONTAINMENT_ROUTE_THROTTLE);
      }
    }

    const registrarIntegration = new HttpLambdaIntegration("PortalRegistrar", registrar.fn);
    const approverIntegration = new HttpLambdaIntegration("PortalApprover", approver.fn);
    const route = (
      path: string,
      methods: HttpMethod[],
      integration: HttpLambdaIntegration,
    ): void => {
      props.httpApi.addRoutes({ path, methods, integration, authorizer: props.authorizer });
    };
    route("/api/v1/registrations", [HttpMethod.POST], registrarIntegration);
    route("/api/v1/registrations/{record_id}", [HttpMethod.PUT, HttpMethod.DELETE], registrarIntegration);
    route("/api/v1/registrations/{record_id}/submit", [HttpMethod.POST], registrarIntegration);
    route("/api/v1/registrations/{record_id}/approve", [HttpMethod.POST], approverIntegration);
    route("/api/v1/registrations/{record_id}/reject", [HttpMethod.POST], approverIntegration);
    // An agent's life after approval. Both are decisions, so they belong to the approver
    // function: retiring sets the record's status, and a review attestation writes the audit
    // trail only. The registrar function cannot do either.
    route("/api/v1/registrations/{record_id}/retire", [HttpMethod.POST], approverIntegration);
    route("/api/v1/registrations/{record_id}/review", [HttpMethod.POST], approverIntegration);
  }
}
