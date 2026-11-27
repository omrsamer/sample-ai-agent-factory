/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: MIT-0
 */
import { Duration, RemovalPolicy, Stack } from "aws-cdk-lib";
import { HttpApi, HttpMethod, IHttpRouteAuthorizer } from "aws-cdk-lib/aws-apigatewayv2";
import { HttpLambdaIntegration } from "aws-cdk-lib/aws-apigatewayv2-integrations";
import { AttributeType, BillingMode, Table, TableEncryption } from "aws-cdk-lib/aws-dynamodb";
import { Effect, ManagedPolicy, PolicyStatement, Role, ServicePrincipal } from "aws-cdk-lib/aws-iam";
import { IKey } from "aws-cdk-lib/aws-kms";
import { Architecture, Code, Function as LambdaFunction, Runtime, Tracing } from "aws-cdk-lib/aws-lambda";
import { LogGroup, RetentionDays } from "aws-cdk-lib/aws-logs";
import { NagSuppressions } from "cdk-nag";
import { Construct } from "constructs";
import { PortalEnvironment, PortalRole } from "./naming";

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
  readonly groupRoleMap: Readonly<Record<string, PortalRole>>;
  /** Group or app-role name to the tenant ids its members may register for. */
  readonly groupTenantMap: Readonly<Record<string, readonly string[]>>;
  readonly allowedOrigins: readonly string[];
  readonly logRetention?: RetentionDays;
  readonly logsKey?: IKey;
}

interface ActionFunctionSpec {
  readonly id: string;
  readonly actionRole: "registrar" | "approver";
  readonly roleName: string;
  readonly handler: string;
  readonly registryActions: readonly string[];
  readonly auditActions: readonly string[];
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

  constructor(scope: Construct, id: string, props: PortalActionsProps) {
    super(scope, id);
    const stack = Stack.of(this);
    const recordsArn = `${props.registryArn}/record/*`;

    const build = (spec: ActionFunctionSpec): { role: Role; fn: LambdaFunction } => {
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
          new PolicyStatement({
            sid: "RegistryRecords",
            effect: Effect.ALLOW,
            actions: [...spec.registryActions],
            resources: [props.registryArn, recordsArn],
          }),
          new PolicyStatement({
            sid: "AuditTrail",
            effect: Effect.ALLOW,
            actions: [...spec.auditActions],
            resources: [props.auditTable.tableArn],
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
        reservedConcurrentExecutions: 5,
        tracing: Tracing.ACTIVE,
        logGroup: logs,
        environment: {
          PORTAL_ENV: props.environment,
          PORTAL_ACTION_ROLE: spec.actionRole,
          PORTAL_REGISTRY_ID: props.registryId,
          PORTAL_REGISTRY_REGION: stack.region,
          PORTAL_AUDIT_TABLE: props.auditTable.tableName,
          PORTAL_IDENTITY_PROVIDER: props.identityProvider,
          PORTAL_GROUP_ROLE_MAP: JSON.stringify(props.groupRoleMap),
          PORTAL_GROUP_TENANT_MAP: JSON.stringify(props.groupTenantMap),
          PORTAL_ALLOWED_ORIGINS: stack.toJsonString(props.allowedOrigins),
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
      return { role, fn };
    };

    const registrar = build({
      id: "Registrar",
      actionRole: "registrar",
      roleName: portalRegistrarRoleName(props.environment),
      handler: "registrar_handler.handler",
      registryActions: PORTAL_REGISTRAR_REGISTRY_ACTIONS,
      auditActions: PORTAL_REGISTRAR_AUDIT_ACTIONS,
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
      description:
        "Agent Factory Portal approver: approves or rejects a submitted agent governance record. Cannot create or change one.",
    });
    this.registrarRole = registrar.role;
    this.approverRole = approver.role;

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
  }
}
