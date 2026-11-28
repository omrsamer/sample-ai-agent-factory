/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: MIT-0
 */
import { Duration, RemovalPolicy, Stack } from "aws-cdk-lib";
import {
  AccountRecovery,
  CfnUserPoolGroup,
  ClientAttributes,
  FeaturePlan,
  Mfa,
  OAuthScope,
  ProviderAttribute,
  StandardThreatProtectionMode,
  UserPool,
  UserPoolClient,
  UserPoolClientIdentityProvider,
  UserPoolDomain,
  UserPoolIdentityProviderSaml,
  UserPoolIdentityProviderSamlMetadata,
} from "aws-cdk-lib/aws-cognito";
import { Construct } from "constructs";
import {
  PORTAL_COGNITO_GROUPS,
  PortalEnvironment,
  PortalRole,
} from "./naming";

export interface PortalCognitoIdentityProps {
  readonly environment: PortalEnvironment;
  /** HTTPS origins of the portal (no trailing slash). The first is the primary. */
  readonly portalOrigins: readonly string[];
  /**
   * SAML metadata URL of the workforce identity source, normally the AWS IAM
   * Identity Center application created for the portal. When set, users sign
   * in through it and the user pool holds no passwords of its own.
   */
  readonly samlMetadataUrl?: string;
  /** SAML attribute that carries the user's group names. */
  readonly samlGroupsAttribute?: string;
  /** Retain the user pool when the stack is deleted. Defaults to true for prod. */
  readonly retainUserPool?: boolean;
}

/**
 * Amazon Cognito sign-in for the portal: one user pool, one public app client
 * using the authorization code grant with PKCE, a hosted sign-in domain and
 * one group per persona. Workforce identities come from AWS IAM Identity
 * Center over SAML when a metadata URL is supplied.
 */
export class PortalCognitoIdentity extends Construct {
  readonly userPool: UserPool;
  readonly client: UserPoolClient;
  readonly domain: UserPoolDomain;
  /** OIDC issuer the API's JWT authorizer validates against. */
  readonly issuer: string;
  /** Hosted sign-in base URL. */
  readonly hostedUiBaseUrl: string;
  /** Group name (or SAML group value) to portal role. */
  readonly groupRoleMap: Readonly<Record<string, PortalRole>>;

  constructor(scope: Construct, id: string, props: PortalCognitoIdentityProps) {
    super(scope, id);
    const stack = Stack.of(this);
    if (props.portalOrigins.length === 0) {
      throw new Error("Portal identity: at least one portal origin is required.");
    }
    const retain = props.retainUserPool ?? props.environment === "prod";
    const federated = props.samlMetadataUrl !== undefined;

    this.userPool = new UserPool(this, "UserPool", {
      userPoolName: `agenticai-portal-${props.environment}`,
      selfSignUpEnabled: false,
      signInAliases: { email: true },
      signInCaseSensitive: false,
      mfa: Mfa.REQUIRED,
      mfaSecondFactor: { otp: true, sms: false },
      passwordPolicy: {
        minLength: 14,
        requireDigits: true,
        requireLowercase: true,
        requireUppercase: true,
        requireSymbols: true,
        tempPasswordValidity: Duration.days(1),
      },
      accountRecovery: AccountRecovery.EMAIL_ONLY,
      featurePlan: FeaturePlan.PLUS,
      standardThreatProtectionMode: StandardThreatProtectionMode.FULL_FUNCTION,
      deletionProtection: retain,
      removalPolicy: retain ? RemovalPolicy.RETAIN : RemovalPolicy.DESTROY,
    });

    for (const [group, role] of Object.entries(PORTAL_COGNITO_GROUPS)) {
      new CfnUserPoolGroup(this, `Group-${group}`, {
        userPoolId: this.userPool.userPoolId,
        groupName: group,
        description: `Agent Factory Portal persona group (role: ${role}).`,
      });
    }
    this.groupRoleMap = { ...PORTAL_COGNITO_GROUPS };

    let saml: UserPoolIdentityProviderSaml | undefined;
    if (props.samlMetadataUrl !== undefined) {
      if (!/^https:\/\/[^\s]+$/.test(props.samlMetadataUrl)) {
        throw new Error("Portal identity: samlMetadataUrl must be an https URL.");
      }
      saml = new UserPoolIdentityProviderSaml(this, "WorkforceIdentity", {
        userPool: this.userPool,
        name: "workforce",
        metadata: UserPoolIdentityProviderSamlMetadata.url(props.samlMetadataUrl),
        attributeMapping: {
          email: ProviderAttribute.other("email"),
          custom: {
            "custom:groups": ProviderAttribute.other(props.samlGroupsAttribute ?? "groups"),
          },
        },
      });
    }

    this.domain = this.userPool.addDomain("Domain", {
      cognitoDomain: {
        domainPrefix: `agenticai-portal-${props.environment}-${stack.account}`,
      },
    });

    this.client = this.userPool.addClient("WebClient", {
      userPoolClientName: `agenticai-portal-web-${props.environment}`,
      generateSecret: false,
      authFlows: { userSrp: !federated },
      // A local user signs in with SRP and so holds a token that can change that user's own
      // attributes, as far as this client may write them. The portal shows people by their
      // email, so the client may write none of the attributes the portal reads. Amazon Cognito
      // reads an empty list as "every standard attribute", so one attribute the portal never
      // reads is named. With a workforce identity provider the mapped attributes must stay
      // writable for sign-in to work, and no SRP sign-in exists.
      writeAttributes: federated ? undefined : new ClientAttributes().withStandardAttributes({ locale: true }),
      preventUserExistenceErrors: true,
      enableTokenRevocation: true,
      accessTokenValidity: Duration.minutes(60),
      idTokenValidity: Duration.minutes(60),
      refreshTokenValidity: Duration.hours(8),
      supportedIdentityProviders: [
        federated
          ? UserPoolClientIdentityProvider.custom("workforce")
          : UserPoolClientIdentityProvider.COGNITO,
      ],
      oAuth: {
        flows: { authorizationCodeGrant: true },
        scopes: [OAuthScope.OPENID, OAuthScope.EMAIL, OAuthScope.PROFILE],
        callbackUrls: props.portalOrigins.map((origin) => `${origin}/auth/callback`),
        logoutUrls: props.portalOrigins.map((origin) => `${origin}/`),
      },
    });
    if (saml) this.client.node.addDependency(saml);

    this.issuer = `https://cognito-idp.${stack.region}.amazonaws.com/${this.userPool.userPoolId}`;
    this.hostedUiBaseUrl = this.domain.baseUrl();
  }
}

export interface PortalEntraIdentityProps {
  /** Microsoft Entra ID tenant (directory) id. */
  readonly tenantId: string;
  /** Application (client) id of the portal single-page application. */
  readonly spaClientId: string;
  /**
   * Audience of the access token the portal API accepts: the application id
   * URI or client id of the API registration.
   */
  readonly apiAudience: string;
  /** Delegated scope the single-page application requests for the API. */
  readonly apiScope: string;
  /** Entra app role or group object id to portal role. */
  readonly groupRoleMap: Readonly<Record<string, PortalRole>>;
}

const GUID = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

/** Validates Entra settings and derives the issuer and its signing keys' location; creates no AWS resource. */
export function resolvePortalEntraIdentity(props: PortalEntraIdentityProps): {
  readonly issuer: string;
  readonly audience: readonly string[];
  /** Where the tenant publishes its token signing keys. */
  readonly jwksUrl: string;
} {
  if (!GUID.test(props.tenantId)) {
    throw new Error("Portal identity: Entra tenantId must be a GUID.");
  }
  if (!GUID.test(props.spaClientId)) {
    throw new Error("Portal identity: Entra spaClientId must be a GUID.");
  }
  if (props.apiAudience.trim().length === 0 || props.apiScope.trim().length === 0) {
    throw new Error("Portal identity: Entra apiAudience and apiScope are required.");
  }
  if (Object.keys(props.groupRoleMap).length === 0) {
    throw new Error(
      "Portal identity: Entra groupRoleMap must map at least one app role or group to a portal role.",
    );
  }
  return {
    issuer: `https://login.microsoftonline.com/${props.tenantId}/v2.0`,
    audience: [props.apiAudience],
    jwksUrl: `https://login.microsoftonline.com/${props.tenantId}/discovery/v2.0/keys`,
  };
}
