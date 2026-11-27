"""Native adapter. No AWS call occurs during import or package authoring."""
if not __debug__:
    raise RuntimeError("Optimized Python is forbidden")
import hashlib
import json
import os
import time
from decimal import Decimal
from protocol import Engine, Refused, canonical, require, safe_metadata, native_failure


ROUTES = {
    "bedrock-agentcore-control": frozenset({
        "create_workload_identity", "get_workload_identity", "delete_workload_identity",
        "create_oauth2_credential_provider", "get_oauth2_credential_provider",
        "update_oauth2_credential_provider", "delete_oauth2_credential_provider",
        "list_tags_for_resource"}),
    "secretsmanager": frozenset({"get_secret_value", "describe_secret", "delete_secret"}),
}


class Native:
    def __init__(self, region, factory=None):
        self.region, self.clients, self.calls = region, {}, 0
        self.factory = factory or self.sdk_client

    def sdk_client(self, service):
        import boto3
        from botocore.config import Config
        return boto3.Session(region_name=self.region).client(service, config=Config(
            retries={"total_max_attempts": 1, "mode": "standard"},
            connect_timeout=5, read_timeout=20, proxies={}))

    def __call__(self, gate, service, method, **kwargs):
        gate()
        require(method in ROUTES.get(service, ()), "Native route is forbidden")
        require(self.calls < 240, "Bounded native route budget exhausted")
        if service not in self.clients:
            self.clients[service] = self.factory(service)
        client = self.clients[service]
        dispatch = getattr(client, method)
        gate()  # Factory/method lookup may take time. This is the last pre-dispatch gate.
        self.calls += 1
        return dispatch(**kwargs)


def plain(value):
    if isinstance(value, Decimal):
        require(value == value.to_integral_value(), "Ledger numeric field differs")
        return int(value)
    if isinstance(value, dict):
        return {k: plain(v) for k, v in value.items()}
    if isinstance(value, list):
        return [plain(v) for v in value]
    return value


class Ledger:
    """Single-item conditional writes, consistent readback; no batch/scan/delete/TTL."""
    def __init__(self, table_name, region, gate, factory=None):
        self.name, self.region, self.gate = table_name, region, gate
        self.factory, self.table, self.calls = factory or self.sdk_table, None, 0

    def sdk_table(self):
        import boto3
        from botocore.config import Config
        return boto3.Session(region_name=self.region).resource("dynamodb", config=Config(
            retries={"total_max_attempts": 1, "mode": "standard"},
            connect_timeout=5, read_timeout=20, proxies={})).Table(self.name)

    def dispatch(self, method, **kwargs):
        self.gate()
        require(method in {"get_item", "put_item"} and self.calls < 160, "Ledger route/budget differs")
        if self.table is None:
            self.table = self.factory()
        dispatch = getattr(self.table, method)
        self.gate()
        self.calls += 1
        try:
            response = dispatch(**kwargs)
        except Exception as error:
            refused = Refused("Ledger SDK dispatch failed; no blind replay")
            refused.native_failure = native_failure(error, "dynamodb", method, "conditional-ledger")
            raise refused from None
        safe_metadata(response, 200)
        return response

    def read(self, key):
        return plain(self.dispatch("get_item", Key={"pk": key}, ConsistentRead=True).get("Item"))

    def claim(self, key, row):
        from boto3.dynamodb.conditions import Attr
        require("pk" not in row and "revision" not in row)
        item = {**row, "pk": key, "revision": 0}
        self.dispatch("put_item", Item=item, ConditionExpression=Attr("pk").not_exists())
        require(self.read(key) == item, "Acknowledged ledger claim readback differs")

    def transition(self, key, old, new, fields):
        from boto3.dynamodb.conditions import Attr
        require(isinstance(fields, dict) and not set(fields).intersection({"pk", "revision", "state"}))
        row = self.read(key)
        require(row is not None and row["state"] == old)
        item = {**row, **fields, "state": new, "revision": row["revision"] + 1}
        self.dispatch("put_item", Item=item,
            ConditionExpression=Attr("state").eq(old) & Attr("revision").eq(row["revision"]))
        require(self.read(key) == item, "Acknowledged ledger transition readback differs")

    def handoff(self, key, previous, fields):
        """Single exact-version CAS; retain immutable history before calling this."""
        from boto3.dynamodb.conditions import Attr
        require(previous["state"] == "DELETED_ABSENT"
                and not set(fields).intersection({"pk", "revision"}))
        row = self.read(key)
        require(row == previous, "Closed generation changed before handoff")
        item = {**row, **fields, "revision": row["revision"] + 1}
        self.dispatch("put_item", Item=item,
            ConditionExpression=Attr("state").eq("DELETED_ABSENT")
            & Attr("revision").eq(row["revision"])
            & Attr("cfnRequestId").eq(row["cfnRequestId"]))
        require(self.read(key) == item, "Acknowledged generation handoff differs")


def load_config(context):
    require(context.function_version.isdigit() and int(context.function_version) > 0,
            "Broker must run as a published immutable version")
    raw = os.environ["BROKER_CONFIG"]
    require(len(raw.encode()) <= 3000)
    require(hashlib.sha256(raw.encode()).hexdigest() == os.environ["BROKER_CONFIG_SHA256"])
    config = json.loads(raw)
    require(set(config) == {"account", "region", "stage", "owner", "logicalResourceId", "stackName",
                            "sourceSecretArn", "sourceSecretVersion", "oauth", "brokerFunctionName",
                            "ledgerTableName", "sourceRoleArn", "sourceFunctionArn"})
    expected = (f"arn:aws:lambda:{config['region']}:{config['account']}:function:"
                + config["brokerFunctionName"] + ":" + context.function_version)
    require(context.invoked_function_arn == expected, "Broker version/account context differs")
    require(not any(k.startswith("AWS_ENDPOINT_URL") or k == "AWS_CA_BUNDLE" for k in os.environ),
            "Custom AWS transport is forbidden")
    return config


def lambda_handler(event, context):
    """Never log event, SDK exception, source secret, credential or token."""
    try:
        config = load_config(context)
        native = Native(config["region"])
        engine = Engine(config, native, None)
        engine.ledger = Ledger(config["ledgerTableName"], config["region"], engine.gate)
        # Deadline includes Lambda's remaining-time bound; caller cannot extend it.
        require(type(event.get("notAfter")) is int and event["notAfter"]
                < time.time() + context.get_remaining_time_in_millis() / 1000 - 5)
        return engine.handle(event)
    except Exception as error:
        result = {"ok": False, "phase": "immutable-runtime-contract",
                "errorClass": type(error).__name__, "automaticMutationRetryAllowed": False,
                "unknownOrPartialDispatchRequiresReadOnlyReconciliation": True}
        if getattr(error, "native_failure", None) is not None:
            result["nativeFailure"] = error.native_failure
        return result
