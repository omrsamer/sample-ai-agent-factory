"""Prospective broker: owns native Create responses; caller receipts confer no authority."""
if not __debug__:
    raise RuntimeError("Optimized Python is forbidden")
import hashlib
import json
import re
import time


class Refused(Exception):
    pass


def require(value, reason="Exact broker contract differs"):
    if not value:
        raise Refused(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def error_code(error):
    return getattr(error, "response", {}).get("Error", {}).get("Code")

def typed_absence(error, service):
    """Require the exact modeled missing-resource status and native request ID."""
    expected = {"bedrock-agentcore-control": 404, "secretsmanager": 400}
    response = getattr(error, "response", None)
    if service not in expected or not isinstance(response, dict):
        return False
    detail, metadata = response.get("Error"), response.get("ResponseMetadata")
    if not isinstance(detail, dict) or not isinstance(metadata, dict):
        return False
    request_id = metadata.get("RequestId")
    return (detail.get("Code") == "ResourceNotFoundException"
            and type(metadata.get("HTTPStatusCode")) is int
            and metadata["HTTPStatusCode"] == expected[service]
            and isinstance(request_id, str)
            and re.fullmatch(r"[A-Za-z0-9_.:-]{1,256}", request_id) is not None)


def native_failure(error, service, method, phase):
    """Allowlisted public SDK metadata; never message text, arguments or response bodies."""
    response = getattr(error, "response", {})
    if not isinstance(response, dict):
        response = {}
    metadata = response.get("ResponseMetadata", {})
    metadata = metadata if isinstance(metadata, dict) else {}
    code = error_code(error)
    request_id = metadata.get("RequestId")
    status = metadata.get("HTTPStatusCode")
    result = {"service": service, "method": method, "phase": phase,
              "errorClass": type(error).__name__}
    if isinstance(code, str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,256}", code):
        result["awsErrorCode"] = code
    if isinstance(request_id, str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,256}", request_id):
        result["awsRequestId"] = request_id
    if type(status) is int and 100 <= status <= 599:
        result["httpStatus"] = status
    return result


def safe_metadata(response, status):
    metadata = response.get("ResponseMetadata", {})
    request_id = metadata.get("RequestId")
    require(metadata.get("HTTPStatusCode") == status and isinstance(request_id, str)
            and re.fullmatch(r"[A-Za-z0-9_.:-]{1,256}", request_id),
            "Native successful response is required")
    return {"httpStatus": status, "requestId": request_id}


class Engine:
    """SDK and atomic ledger are injected. No caller-supplied ARN/name/tags/receipt."""
    def __init__(self, config, native, ledger, clock=time.time, sleep=time.sleep):
        self.config, self.native, self.ledger, self.clock, self.sleep = config, native, ledger, clock, sleep
        self.account, self.region, self.stage = config["account"], config["region"], config["stage"]
        require(re.fullmatch(r"\d{12}", self.account) and self.region == "eu-west-1")
        require(self.stage in {"nonprod", "prod"})
        self.tags = config["owner"]
        require(set(self.tags) == {"deployment-scope", "application-id", "tenant-id",
                                  "agent-id", "cost-centre", "environment"})
        require(self.tags["deployment-scope"] == "fresh-security-remediation"
                and self.tags["environment"] == self.stage
                and all(isinstance(v, str) and 0 < len(v) <= 256 for v in self.tags.values()))
        require(re.fullmatch(r"[A-Za-z0-9_-]{1,32}", self.tags["tenant-id"])
                and re.fullmatch(r"[A-Za-z0-9_-]{1,32}", self.tags["agent-id"]))
        self.prefix = f"AgenticAI_D03_{self.stage}_{self.tags['tenant-id']}_{self.tags['agent-id']}".replace("-", "_")
        self.provider = self.prefix + "_inference"
        self.base = f"arn:aws:bedrock-agentcore:{self.region}:{self.account}:"
        self.directory, self.vault = self.base + "workload-identity-directory/default", self.base + "token-vault/default"
        self.provider_arn = self.vault + "/oauth2credentialprovider/" + self.provider
        self.secret_prefix = (
            f"arn:aws:secretsmanager:{self.region}:{self.account}:secret:"
            f"bedrock-agentcore-identity!default/oauth2/{self.provider}-")
        self.allocation = digest({"account": self.account, "region": self.region, "owner": self.tags})
        self.config_hash = digest(config)
        self.deadline = None
        self.phase = "envelope"
        self.current_request = None
        self.last_native_failure = None

    def gate(self):
        require(self.deadline is not None and self.clock() < self.deadline, "Broker deadline expired")

    def call(self, service, method, **kwargs):
        self.gate()
        # Native adapter repeats this gate after SDK client and method lookup.
        self.last_native_failure = None
        try:
            return self.native(self.gate, service, method, **kwargs)
        except Exception as error:
            self.last_native_failure = native_failure(error, service, method, self.phase)
            raise

    def owner_key(self, arn):
        return self.allocation + "#OWNER#" + hashlib.sha256(arn.encode()).hexdigest()

    def history_key(self, arn, request_id):
        return self.owner_key(arn) + "#CLOSED#" + request_id

    def request_key(self, request_id):
        return self.allocation + "#REQUEST#" + request_id

    def envelope(self, event):
        require(isinstance(event, dict) and set(event) == {
            "schema", "requestType", "stackId", "logicalResourceId", "requestId",
            "physicalResourceId", "notAfter"})
        require(event["schema"] == 1 and event["requestType"] in {"Create", "Update", "Delete"})
        require(event["logicalResourceId"] == self.config["logicalResourceId"])
        require(re.fullmatch(
            re.escape(f"arn:aws:cloudformation:{self.region}:{self.account}:stack/"
                      + self.config["stackName"] + "/")
            + r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
            event["stackId"]))
        require(re.fullmatch(r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
                             event["requestId"]))
        require(type(event["notAfter"]) is int and self.clock() < event["notAfter"] <= self.clock() + 580)
        require(isinstance(event["physicalResourceId"], str) and len(event["physicalResourceId"]) <= 300)
        if event["requestType"] == "Create":
            require(event["physicalResourceId"] == "")
        else:
            self.physical_identity(event["physicalResourceId"])
        self.deadline = event["notAfter"]
        self.current_request = event

    def physical_identity(self, physical):
        pieces = physical.split("|")
        require(len(pieces) == 2 and pieces[0] == self.provider)
        require(re.fullmatch(re.escape(self.prefix) + r"_[a-f0-9]{12}", pieces[1]))
        return pieces[1]

    def identity_arn(self, name):
        require(re.fullmatch(re.escape(self.prefix) + r"_[a-f0-9]{12}", name))
        return self.directory + "/workload-identity/" + name

    def managed_secret(self, response):
        value = response.get("clientSecretArn")
        value = value.get("secretArn") if isinstance(value, dict) else value
        require(isinstance(value, str) and re.fullmatch(re.escape(self.secret_prefix) + r"[A-Za-z0-9_-]{1,128}", value))
        return value

    def source_config(self):
        row = self.config
        response = self.call("secretsmanager", "get_secret_value",
                             SecretId=row["sourceSecretArn"], VersionId=row["sourceSecretVersion"])
        require(response.get("ARN") == row["sourceSecretArn"]
                and response.get("VersionId") == row["sourceSecretVersion"])
        safe_metadata(response, 200)
        raw = response.get("SecretString")
        require(isinstance(raw, str) and len(raw.encode()) <= 16_384)
        value = json.loads(raw)
        for field in ("clientId", "scope", "issuer", "authorizationEndpoint", "tokenEndpoint"):
            require(value.get(field) == row["oauth"][field], "Immutable public OAuth binding differs")
        require(isinstance(value.get("clientSecret"), str) and 0 < len(value["clientSecret"]) <= 2048)
        return {"includedOauth2ProviderConfig": {
            field: value[field] for field in ("clientId", "clientSecret", "issuer",
                                             "authorizationEndpoint", "tokenEndpoint")}}

    def matching_owner(self, row):
        require(row is not None and row["stackId"] == self.current_request["stackId"]
                and row["logicalResourceId"] == self.current_request["logicalResourceId"]
                and row["allocation"] == self.allocation
                and row["configSha256"] == self.config_hash)
        receipt = row.get("creatorReceipt")
        require(isinstance(receipt, dict) and receipt["httpStatus"] == 201 and receipt["requestId"])
        return receipt

    def live(self, kind, name, receipt, empty=False):
        method = "get_workload_identity" if kind == "identity" else "get_oauth2_credential_provider"
        response = self.call("bedrock-agentcore-control", method, name=name)
        arn = self.identity_arn(name) if kind == "identity" else self.provider_arn
        require(response.get("name") == name)
        require(response.get("workloadIdentityArn" if kind == "identity" else "credentialProviderArn") == arn)
        require(receipt["arn"] == arn and receipt["name"] == name)
        if kind == "provider":
            require(self.managed_secret(response) == receipt["managedSecretArn"])
        tags = self.call("bedrock-agentcore-control", "list_tags_for_resource", resourceArn=arn).get("tags")
        require(tags == ({} if empty else self.tags), "Live tags differ; no adoption")
        return arn

    def reserve(self, kind, name):
        arn = self.identity_arn(name) if kind == "identity" else self.provider_arn
        key = self.owner_key(arn)
        row = {"allocation": self.allocation, "configSha256": self.config_hash,
               "stackId": self.current_request["stackId"],
               "logicalResourceId": self.current_request["logicalResourceId"], "kind": kind, "name": name,
               "arn": arn, "cfnRequestId": self.current_request["requestId"], "state": "CREATE_INTENT"}
        self.gate()
        previous = self.ledger.read(key)
        if previous is None:
            self.ledger.claim(key, row)  # Conditional, acknowledged BEFORE native Create.
            self.phase = kind + "-new-generation-fresh-absence"
            try:
                self.call("bedrock-agentcore-control",
                          "get_workload_identity" if kind == "identity" else "get_oauth2_credential_provider",
                          name=name)
            except Exception as error:
                require(typed_absence(error, "bedrock-agentcore-control"),
                        "Fresh new child absence is required")
                self.last_native_failure = None
            else:
                raise Refused("Existing child forbids Create/adoption")
        else:
            # A new generation can reuse only our durably closed, exactly absent child.
            # Old creator proof is archived immutably before a conditional handoff.
            require(previous["state"] == "DELETED_ABSENT"
                    and previous["allocation"] == self.allocation
                    and previous["configSha256"] == self.config_hash
                    and previous["kind"] == kind and previous["name"] == name
                    and previous["arn"] == arn
                    and previous["cfnRequestId"] != self.current_request["requestId"],
                    "Prior incomplete/foreign generation forbids Create")
            receipt = previous.get("creatorReceipt")
            require(isinstance(receipt, dict) and receipt["httpStatus"] == 201
                    and receipt["arn"] == arn and receipt["name"] == name)
            self.phase = kind + "-closed-generation-fresh-absence"
            try:
                self.call("bedrock-agentcore-control",
                          "get_workload_identity" if kind == "identity" else "get_oauth2_credential_provider",
                          name=name)
            except Exception as error:
                require(typed_absence(error, "bedrock-agentcore-control"),
                        "Fresh child absence is required before generation handoff")
                self.last_native_failure = None
            else:
                raise Refused("Reappeared child forbids generation handoff/adoption")
            if kind == "provider":
                require(re.fullmatch(re.escape(self.secret_prefix) + r"[A-Za-z0-9_-]{1,128}",
                                     receipt["managedSecretArn"]))
                try:
                    self.call("secretsmanager", "describe_secret", SecretId=receipt["managedSecretArn"])
                except Exception as error:
                    require(typed_absence(error, "secretsmanager"),
                            "Fresh exact old managed-secret absence is required")
                    self.last_native_failure = None
                else:
                    raise Refused("Reappeared managed secret forbids generation handoff")
            archived = {k: v for k, v in previous.items() if k not in {"pk", "revision"}}
            history_key = self.history_key(arn, previous["cfnRequestId"])
            history = {"state": "IMMUTABLE_CLOSED_GENERATION", "closedGeneration": archived,
                       "closedGenerationSha256": digest(archived)}
            self.phase = kind + "-closed-generation-archive"
            saved = self.ledger.read(history_key)
            if saved is None:
                self.gate()
                self.ledger.claim(history_key, history)
            else:
                require({k: v for k, v in saved.items() if k not in {"pk", "revision"}} == history,
                        "Immutable closed generation differs")
            self.gate()
            # Compare the exact old generation as well as its state/revision.
            self.ledger.handoff(key, previous, {**row, "creatorReceipt": None,
                                "previousClosedGenerationKey": history_key,
                                "previousClosedGenerationSha256": digest(archived)})

    def create(self, kind, name):
        arn = self.identity_arn(name) if kind == "identity" else self.provider_arn
        key = self.owner_key(arn)
        reserved = self.ledger.read(key)
        require(reserved is not None and reserved["state"] == "CREATE_INTENT"
                and reserved["cfnRequestId"] == self.current_request["requestId"]
                and reserved["stackId"] == self.current_request["stackId"]
                and reserved["logicalResourceId"] == self.current_request["logicalResourceId"]
                and reserved["configSha256"] == self.config_hash
                and reserved["allocation"] == self.allocation
                and reserved["kind"] == kind and reserved["name"] == name and reserved["arn"] == arn,
                "Exact allocation reservation is required")
        self.gate()
        config = self.source_config() if kind == "provider" else None
        self.phase = kind + "-create-dispatch"
        self.ledger.transition(key, "CREATE_INTENT", "CREATE_DISPATCHED", {})
        self.gate()
        try:
            if kind == "identity":
                response = self.call("bedrock-agentcore-control", "create_workload_identity",
                                     name=name, tags=self.tags)
            else:
                response = self.call("bedrock-agentcore-control", "create_oauth2_credential_provider",
                    name=name, credentialProviderVendor="CognitoOauth2",
                    oauth2ProviderConfigInput=config, tags=self.tags)
                del config
            receipt = {**safe_metadata(response, 201), "kind": kind, "name": name, "arn": arn,
                       "requestTagsSha256": digest(self.tags),
                       "responseReceivedAtEpochSeconds": int(self.clock())}
            require(response.get("name") == name and response.get(
                "workloadIdentityArn" if kind == "identity" else "credentialProviderArn") == arn)
            if kind == "provider":
                receipt["managedSecretArn"] = self.managed_secret(response)
            self.phase = kind + "-durable-creator-receipt"
            self.gate()
            self.ledger.transition(key, "CREATE_DISPATCHED", "CREATED_TAGGED_UNVERIFIED", {"creatorReceipt": receipt})
            # A response loss here leaves CREATE_DISPATCHED; never authorize adoption/replay.
        except Exception:
            raise Refused("Create dispatch or receipt persistence uncertain; no adoption/replay") from None
        self.gate()
        owned = self.ledger.read(key)
        self.matching_owner(owned)
        require(owned["state"] == "CREATED_TAGGED_UNVERIFIED" and owned["creatorReceipt"] == receipt)
        self.phase = kind + "-atomic-create-live-tag-verification"
        self.live(kind, name, receipt)
        self.gate()
        self.ledger.transition(key, "CREATED_TAGGED_UNVERIFIED", "OWNED_TAGGED", {})
        return receipt

    def owned(self, kind, name):
        arn = self.identity_arn(name) if kind == "identity" else self.provider_arn
        row = self.ledger.read(self.owner_key(arn))
        receipt = self.matching_owner(row)
        require(row["state"] == "OWNED_TAGGED", "Pending/unknown ownership forbids lifecycle write")
        self.live(kind, name, receipt)
        return row, receipt

    def provider_ready(self):
        for _ in range(50):
            response = self.call("bedrock-agentcore-control", "get_oauth2_credential_provider", name=self.provider)
            status = response.get("status")
            if status == "READY":
                return
            require(status in {"CREATING", "UPDATING"}, "Unknown/failed provider status")
            self.sleep(5)
        raise Refused("Provider readiness timed out; no mutator retry")

    def update(self, identity):
        self.owned("identity", identity)
        row, receipt = self.owned("provider", self.provider)
        key = self.owner_key(self.provider_arn)
        config = self.source_config()
        self.phase = "provider-update-dispatch"
        self.ledger.transition(key, "OWNED_TAGGED", "UPDATE_DISPATCHED", {})
        self.gate()
        response = self.call("bedrock-agentcore-control", "update_oauth2_credential_provider",
                             name=self.provider, credentialProviderVendor="CognitoOauth2",
                             oauth2ProviderConfigInput=config)
        del config
        update_receipt = safe_metadata(response, 200)
        self.provider_ready()
        self.live("provider", self.provider, receipt)
        self.gate()
        self.ledger.transition(key, "UPDATE_DISPATCHED", "OWNED_TAGGED",
                               {"lastUpdateReceipt": update_receipt})

    def delete(self, kind, name):
        row, receipt = self.owned(kind, name)
        key = self.owner_key(receipt["arn"])
        self.phase = kind + "-delete-dispatch"
        self.ledger.transition(key, "OWNED_TAGGED", "DELETE_DISPATCHED", {})
        self.gate()
        response = self.call("bedrock-agentcore-control",
            "delete_workload_identity" if kind == "identity" else "delete_oauth2_credential_provider", name=name)
        delete_receipt = safe_metadata(response, 204)
        # No blind replay, even if the response was lost or deletion is delayed.
        self.gate()
        self.ledger.transition(key, "DELETE_DISPATCHED", "DELETE_RESPONSE_RECEIVED",
                               {"deleteReceipt": delete_receipt})
        for _ in range(24):
            try:
                response = self.call("bedrock-agentcore-control",
                    "get_workload_identity" if kind == "identity" else "get_oauth2_credential_provider",
                    name=name)
            except Exception as error:
                if not typed_absence(error, "bedrock-agentcore-control"):
                    raise
                self.last_native_failure = None
                break
            # An existing resource must still be exactly the recorded child.
            require(response.get("name") == name and response.get(
                "workloadIdentityArn" if kind == "identity" else "credentialProviderArn") == receipt["arn"])
            self.sleep(5)
        else:
            raise Refused("Delete absence wait expired; no mutator replay")
        if kind == "provider":
            # No source secret is described or deleted. Only the native 201's exact managed secret.
            try:
                secret = self.call("secretsmanager", "describe_secret", SecretId=receipt["managedSecretArn"])
            except Exception as error:
                if not typed_absence(error, "secretsmanager"):
                    raise
                self.last_native_failure = None
            else:
                require(secret.get("ARN") == receipt["managedSecretArn"])
                if not secret.get("DeletedDate"):
                    self.phase = "provider-managed-secret-cleanup-dispatch"
                    self.ledger.transition(key, "DELETE_RESPONSE_RECEIVED", "SECRET_DELETE_DISPATCHED", {})
                    self.gate()
                    response = self.call("secretsmanager", "delete_secret",
                        SecretId=receipt["managedSecretArn"], ForceDeleteWithoutRecovery=True)
                    secret_delete_receipt = safe_metadata(response, 200)
                    require(response.get("ARN") == receipt["managedSecretArn"])
                    # A successful request is not proof of absence.
                    for _ in range(24):
                        try:
                            secret = self.call("secretsmanager", "describe_secret",
                                               SecretId=receipt["managedSecretArn"])
                        except Exception as error:
                            if not typed_absence(error, "secretsmanager"):
                                raise
                            self.last_native_failure = None
                            break
                        require(secret.get("ARN") == receipt["managedSecretArn"])
                        self.sleep(5)
                    else:
                        raise Refused("Managed secret absence wait expired; no deletion replay")
                    self.gate()
                    self.ledger.transition(key, "SECRET_DELETE_DISPATCHED", "DELETE_RESPONSE_RECEIVED",
                                           {"managedSecretDeleteReceipt": secret_delete_receipt})
                else:
                    # Scheduled deletion is not exact absence; require Root's later RO closure.
                    raise Refused("Managed secret deletion pending; exact absence not yet proven")
        self.gate()
        self.ledger.transition(key, "DELETE_RESPONSE_RECEIVED", "DELETED_ABSENT", {})

    def handle(self, event):
        """Return safe metadata only. Pending records require separate RO reconciliation."""
        request_key = None
        self.last_native_failure = None
        try:
            self.envelope(event)
            key = self.request_key(event["requestId"])
            binding = digest({k: v for k, v in event.items() if k != "notAfter"})
            existing = self.ledger.read(key)
            if existing is not None:
                require(existing["bindingSha256"] == binding
                        and existing["configSha256"] == self.config_hash)
                require(existing["state"] == "COMPLETE", "Prior intent/unknown dispatch forbids replay")
                return existing["result"]
            self.gate()
            self.ledger.claim(key, {"state": "CLAIMED", "bindingSha256": binding,
                                  "configSha256": self.config_hash})
            request_key = key
            self.gate()
            if event["requestType"] == "Create":
                identity = self.prefix + "_" + event["requestId"].replace("-", "")[:12]
                # Reserve the fixed provider first. Active or unknown allocations
                # cannot create another request-derived identity.
                self.reserve("provider", self.provider)
                self.reserve("identity", identity)
                self.create("identity", identity)
                self.create("provider", self.provider)
                self.provider_ready()
            else:
                identity = self.physical_identity(event["physicalResourceId"])
                if event["requestType"] == "Update":
                    self.update(identity)
                else:
                    self.delete("provider", self.provider)
                    self.delete("identity", identity)
            result = {"ok": True, "physicalResourceId": self.provider + "|" + identity,
                      "workloadName": identity, "brokerOwnsCreatorReceipts": True,
                      "brokerConfigSha256": self.config_hash,
                      "requestId": event["requestId"], "requestType": event["requestType"]}
            self.gate()
            self.ledger.transition(key, "CLAIMED", "COMPLETE", {"result": result})
            return result
        except Exception as error:
            # No raw exception, SDK request, response, token or secret is exposed.
            failure = self.last_native_failure or getattr(error, "native_failure", None)
            result = {"ok": False, "phase": self.phase, "errorClass": type(error).__name__,
                    "unknownOrPartialDispatchRequiresReadOnlyReconciliation": True,
                    "automaticMutationRetryAllowed": False}
            if failure is not None:
                result["nativeFailure"] = failure
            if request_key is not None:
                try:
                    self.gate()
                    self.ledger.transition(request_key, "CLAIMED", "FAILED_REQUIRES_RECONCILIATION",
                                           {"failure": result})
                except Exception:
                    # The existing durable request intent still forbids replay.
                    result["failureLedgerAcknowledged"] = False
                else:
                    result["failureLedgerAcknowledged"] = True
            return result
