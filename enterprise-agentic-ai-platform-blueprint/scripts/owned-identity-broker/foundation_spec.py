"""Portable offline specification; Root owns all native provisioning."""
if not __debug__:
    raise RuntimeError("Optimized Python is forbidden")
import copy
import hashlib
import json

OWNER = {"application-id": "security-remediation-test", "agent-id": "shared",
         "tenant-id": "shared", "cost-centre": "platform-test",
         "deployment-scope": "fresh-security-remediation"}

def statement(sid, actions, resources, conditions=None):
    row = {"Sid": sid, "Effect": "Allow", "Action": actions, "Resource": resources}
    if conditions:
        row["Condition"] = conditions
    return row

def allocation(label, account, stage, source, owner=None):
    owner = {**(OWNER if owner is None else owner), "environment": stage}
    tenant, agent = owner["tenant-id"], owner["agent-id"]
    name = f"AgenticAI-D03-{stage}-{tenant}-{agent}-idbroker"
    role = f"arn:aws:iam::{account}:role/{name}"
    base = f"arn:aws:bedrock-agentcore:eu-west-1:{account}:"
    prefix = f"AgenticAI_D03_{stage}_{tenant}_{agent}".replace("-", "_")
    provider = prefix + "_inference"
    directory, vault = base + "workload-identity-directory/default", base + "token-vault/default"
    identity = directory + "/workload-identity/" + prefix + "_*"
    provider_arn = vault + "/oauth2credentialprovider/" + provider
    source_function = f"arn:aws:lambda:eu-west-1:{account}:function:AgenticAI-D03-{stage}-{tenant}-{agent}-idprov"
    table = name + "-ledger"
    source_version = (source.get("versionId") or
                      (source["currentVersions"][0] if source.get("currentVersions") else
                       next(k for k, v in source["versionStages"].items() if "AWSCURRENT" in v)))
    return {"label": label, "account": account, "region": "eu-west-1", "stage": stage,
            "owner": owner, "brokerFunctionName": name, "brokerRoleArn": role,
            "sourceFunctionArn": source_function,
            "sourceRoleArn": f"arn:aws:iam::{account}:role/AgenticAI-D03-{stage}-{tenant}-{agent}-idprov",
            "ledgerTableName": table, "directoryArn": directory, "vaultArn": vault,
            "identityFamilyArn": identity, "providerArn": provider_arn, "providerName": provider,
            "sourceSecretArn": source["sourceSecretArn"], "sourceSecretVersion": source_version,
            "sourceKmsKeyArn": source["kmsKeyArn"], "logicalResourceId": "InferenceCredProvider",
            "stackName": f"AgenticAI-{tenant}-{agent}-{stage}-RuntimeMemory",
            "foundationStackName": f"AgenticAI-{tenant}-{agent}-{stage}-IdentityBrokerFoundation"}

def policy(a):
    broker_function = f"arn:aws:lambda:{a['region']}:{a['account']}:function:{a['brokerFunctionName']}"
    region = {"StringEquals": {"aws:PrincipalArn": a["brokerRoleArn"], "aws:RequestedRegion": a["region"]},
              "ArnEquals": {"lambda:SourceFunctionArn": broker_function}}
    tag = copy.deepcopy(region)
    tag["StringEquals"].update({f"aws:RequestTag/{k}": v for k, v in a["owner"].items()})
    tag["ForAllValues:StringEquals"] = {"aws:TagKeys": sorted(a["owner"])}
    tag["Null"] = {"aws:TagKeys": "false"}
    owned = copy.deepcopy(region)
    owned["StringEquals"].update({f"aws:ResourceTag/{k}": v for k, v in a["owner"].items()})
    base = f"arn:aws:secretsmanager:{a['region']}:{a['account']}:secret:bedrock-agentcore-identity!default/oauth2/{a['providerName']}-*"
    allocation_hash = hashlib.sha256(json.dumps(
        {"account": a["account"], "region": a["region"], "owner": a["owner"]},
        sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    statements = [
        statement("Log", ["logs:CreateLogStream", "logs:PutLogEvents"],
                  [f"arn:aws:logs:{a['region']}:{a['account']}:log-group:/aws/lambda/{a['brokerFunctionName']}:*"],
                  {"ArnEquals": {"lambda:SourceFunctionArn": broker_function}}),
        statement("Ledger", ["dynamodb:GetItem", "dynamodb:PutItem"],
                  [f"arn:aws:dynamodb:{a['region']}:{a['account']}:table/{a['ledgerTableName']}"],
                  {"ForAllValues:StringLike": {"dynamodb:LeadingKeys": [allocation_hash + "#*"]},
                   "Null": {"dynamodb:LeadingKeys": "false"},
                   "ArnEquals": {"lambda:SourceFunctionArn": broker_function}}),
        statement("SourceSecret", ["secretsmanager:GetSecretValue"], [a["sourceSecretArn"]],
                  {"ArnEquals": {"lambda:SourceFunctionArn": broker_function}}),
        statement("DecryptOnlyPlatformSecret", ["kms:Decrypt"], [a["sourceKmsKeyArn"]],
                  {"StringEquals": {"kms:ViaService": f"secretsmanager.{a['region']}.amazonaws.com",
                                    "kms:EncryptionContext:SecretARN": a["sourceSecretArn"]}}),
        statement("OnlyOwnManagedProviderSecret", ["secretsmanager:CreateSecret", "secretsmanager:TagResource",
                  "secretsmanager:DeleteSecret"], [base],
                  {"StringEquals": {"aws:PrincipalArn": a["brokerRoleArn"], "aws:RequestedRegion": a["region"]}}),
        statement("DirectManagedSecretRead", ["secretsmanager:DescribeSecret"], [base], region),
        statement("DefaultVaultProviderPrerequisite", ["bedrock-agentcore:CreateTokenVault"], [a["vaultArn"]],
                  {"StringEquals": {"aws:PrincipalArn": a["brokerRoleArn"], "aws:RequestedRegion": a["region"]}}),
        statement("CreateProvider", ["bedrock-agentcore:CreateOauth2CredentialProvider"],
                  [a["vaultArn"], a["providerArn"]], tag),
        statement("CreateIdentity", ["bedrock-agentcore:CreateWorkloadIdentity"],
                  [a["directoryArn"], a["identityFamilyArn"]], tag),
        statement("ReadExactChildAndModeledParents", ["bedrock-agentcore:GetOauth2CredentialProvider",
                  "bedrock-agentcore:GetWorkloadIdentity", "bedrock-agentcore:ListTagsForResource"],
                  [a["directoryArn"], a["identityFamilyArn"], a["vaultArn"], a["providerArn"]], region),
        statement("ProviderChild", ["bedrock-agentcore:UpdateOauth2CredentialProvider",
                  "bedrock-agentcore:DeleteOauth2CredentialProvider"], [a["providerArn"]], owned),
        statement("IdentityChild", ["bedrock-agentcore:DeleteWorkloadIdentity"], [a["identityFamilyArn"]], owned),
        statement("ProviderParent", ["bedrock-agentcore:UpdateOauth2CredentialProvider",
                  "bedrock-agentcore:DeleteOauth2CredentialProvider"], [a["vaultArn"]], region),
        statement("IdentityParent", ["bedrock-agentcore:DeleteWorkloadIdentity"], [a["directoryArn"]], region),
        statement("IsolatedExactSixTagAuthorityIncludingRequiredParents", ["bedrock-agentcore:TagResource"],
                  [a["providerArn"], a["identityFamilyArn"], a["vaultArn"], a["directoryArn"]], tag),
    ]
    return {"Version": "2012-10-17", "Statement": statements}

def foundation(a):
    doc = policy(a)
    ceiling = purpose_ceiling(a)
    require_size(doc, 10240)
    require_size(ceiling, 6144)
    config_pattern = (r"\{.*\}")  # Root must bind the separately reviewed complete config bytes/hash.
    params = {
        "CodeBucket": {"Type": "String", "AllowedPattern": "[a-z0-9.-]{3,63}"},
        "CodeKey": {"Type": "String", "MinLength": 1},
        "CodeVersion": {"Type": "String", "MinLength": 1},
        "CodeSha256": {"Type": "String", "AllowedPattern": "[A-Za-z0-9+/]{43}="},
        "BrokerConfigJson": {"Type": "String", "AllowedPattern": config_pattern, "MaxLength": 3000},
        "BrokerConfigSha256": {"Type": "String", "AllowedPattern": "[a-f0-9]{64}"},
    }
    resources = {
        "PurposeBoundary": {"Type": "AWS::IAM::ManagedPolicy", "Properties": {
            "ManagedPolicyName": a["brokerFunctionName"] + "-PurposeBoundary",
            "PolicyDocument": ceiling}},
        "BrokerRole": {"Type": "AWS::IAM::Role", "Properties": {
            "RoleName": a["brokerFunctionName"], "PermissionsBoundary": {"Ref": "PurposeBoundary"},
            "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]},
            "Policies": [{"PolicyName": "BrokerOwnedLifecycle", "PolicyDocument": doc}],
            "Tags": [{"Key": k, "Value": v} for k, v in sorted(a["owner"].items())]}},
        "OwnershipLedger": {"Type": "AWS::DynamoDB::Table", "DeletionPolicy": "Retain",
            "UpdateReplacePolicy": "Retain", "Properties": {
                "TableName": a["ledgerTableName"], "BillingMode": "PAY_PER_REQUEST",
                "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
                "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
                "DeletionProtectionEnabled": True, "SSESpecification": {"SSEEnabled": True},
                "PointInTimeRecoverySpecification": {"PointInTimeRecoveryEnabled": True},
                "Tags": [{"Key": k, "Value": v} for k, v in sorted(a["owner"].items())]}},
        "BrokerLog": {"Type": "AWS::Logs::LogGroup", "DeletionPolicy": "Retain", "UpdateReplacePolicy": "Retain",
            "Properties": {"LogGroupName": "/aws/lambda/" + a["brokerFunctionName"], "RetentionInDays": 30}},
        "BrokerFunction": {"Type": "AWS::Lambda::Function", "DependsOn": ["BrokerLog", "OwnershipLedger"],
            "Properties": {
                "FunctionName": a["brokerFunctionName"], "Runtime": "python3.13", "Handler": "runtime.lambda_handler",
                "Timeout": 600, "MemorySize": 256, "ReservedConcurrentExecutions": 1,
                "Role": {"Fn::GetAtt": ["BrokerRole", "Arn"]},
                "Code": {"S3Bucket": {"Ref": "CodeBucket"}, "S3Key": {"Ref": "CodeKey"},
                         "S3ObjectVersion": {"Ref": "CodeVersion"}},
                "Environment": {"Variables": {
                    "BROKER_CONFIG": {"Ref": "BrokerConfigJson"},
                    "BROKER_CONFIG_SHA256": {"Ref": "BrokerConfigSha256"}}}}},
        "BrokerVersion": {"Type": "AWS::Lambda::Version", "Properties": {
            "FunctionName": {"Ref": "BrokerFunction"}, "CodeSha256": {"Ref": "CodeSha256"}}},
    }
    return {"AWSTemplateFormatVersion": "2010-09-09", "Description": "Prospective Root-owned exact-allocation identity broker.",
            "Parameters": params, "Resources": resources,
            "Outputs": {"BrokerVersionArn": {"Value": {"Ref": "BrokerVersion"}},
                        "BrokerRoleArn": {"Value": {"Fn::GetAtt": ["BrokerRole", "Arn"]}},
                        "LedgerName": {"Value": {"Ref": "OwnershipLedger"}},
                        "BrokerConfigSha256": {"Value": {"Ref": "BrokerConfigSha256"}}}}

def source_boundary(a):
    # Actual published version is intentionally unresolved and must be substituted only from native proof.
    return {"Version": "2012-10-17", "Statement": [
        statement("InvokeExactImmutableBroker", ["lambda:InvokeFunction"],
                  [{"Ref": "ActualPublishedBrokerVersionArn"}],
                  {"ArnEquals": {"lambda:SourceFunctionArn": a["sourceFunctionArn"]},
                   "StringEquals": {"aws:PrincipalArn": a["sourceRoleArn"], "aws:RequestedRegion": a["region"]}}),
        statement("WriteOwnSourceHandlerLog", ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                  [f"arn:aws:logs:{a['region']}:{a['account']}:log-group:/aws/lambda/{a['sourceFunctionArn'].rsplit(':', 1)[1]}",
                   f"arn:aws:logs:{a['region']}:{a['account']}:log-group:/aws/lambda/{a['sourceFunctionArn'].rsplit(':', 1)[1]}:*"]),
        {"Sid": "DenyDirectIdentitySecretAndTokenAuthority", "Effect": "Deny",
         "Action": ["bedrock-agentcore:*", "secretsmanager:*", "kms:*"], "Resource": "*"},
    ]}

def require_size(doc, maximum):
    size = len(json.dumps(doc, separators=(",", ":"), ensure_ascii=False))
    if size > maximum:
        raise RuntimeError(f"Policy compact characters {size} exceed {maximum}")
    return size

def purpose_ceiling(a):
    """Small boundary ceiling; the sole granular inline policy remains authoritative."""
    original = policy(a)
    direct = [s for s in original["Statement"] if any(x.startswith("bedrock-agentcore:") for x in s["Action"])
              and s["Sid"] != "DefaultVaultProviderPrerequisite"]
    others = [copy.deepcopy(s) for s in original["Statement"] if s not in direct]
    envelope = statement("DirectAgentCoreExactAllocationCeiling",
                         sorted({x for s in direct for x in s["Action"]}),
                         sorted({x for s in direct for x in s["Resource"]}),
                         copy.deepcopy(next(s for s in direct if s["Sid"] == "ReadExactChildAndModeledParents")["Condition"]))
    return {"Version": "2012-10-17", "Statement": [*others, envelope]}

def broker_secret_grant(sid, allocations, secret, kms=False):
    result = {"Sid": sid, "Effect": "Allow",
        "Principal": {"AWS": [f"arn:aws:iam::{a['account']}:root" for a in allocations]},
        "Action": ["kms:Decrypt"] if kms else ["secretsmanager:GetSecretValue"],
        "Resource": "*" if kms else secret,
        "Condition": {"ArnEquals": {"aws:PrincipalArn": [a["brokerRoleArn"] for a in allocations]}}}
    if kms:
        result["Condition"]["StringEquals"] = {
            "kms:ViaService": "secretsmanager.eu-west-1.amazonaws.com",
            "kms:EncryptionContext:SecretARN": secret}
    return result
