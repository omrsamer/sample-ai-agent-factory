#!/usr/bin/env python3
"""Render an explicit reviewed allocation; this command never calls AWS."""
if not __debug__:
    raise RuntimeError("Optimized Python is forbidden")
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import zipfile
from urllib.parse import urlsplit

from foundation_spec import allocation, foundation, policy, purpose_ceiling, source_boundary
from protocol import canonical, digest, require


def reviewed_input(value):
    require(isinstance(value, dict) and set(value) == {"allocation", "oauth"})
    a, oauth = value["allocation"], value["oauth"]
    require(isinstance(a, dict) and isinstance(oauth, dict))
    require(re.fullmatch(r"\d{12}", a["account"]) and a["region"] == "eu-west-1"
            and a["stage"] in {"nonprod", "prod"})
    require(set(a["owner"]) == {"application-id", "agent-id", "tenant-id", "cost-centre",
                                "deployment-scope", "environment"}
            and a["owner"]["environment"] == a["stage"]
            and a["owner"]["deployment-scope"] == "fresh-security-remediation")
    require(all(isinstance(v, str) and 0 < len(v) <= 256 for v in a["owner"].values()))
    require(all(re.fullmatch(r"[A-Za-z0-9_-]{1,32}", a["owner"][k])
                for k in ("tenant-id", "agent-id")))
    require(re.fullmatch(r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
                         a["sourceSecretVersion"]))
    require(re.fullmatch(r"arn:aws:secretsmanager:eu-west-1:\d{12}:secret:[A-Za-z0-9/_+=.@!-]{1,512}",
                         a["sourceSecretArn"]))
    require(re.fullmatch(r"arn:aws:kms:eu-west-1:\d{12}:key/[a-f0-9-]{36}", a["sourceKmsKeyArn"]))
    expected = allocation(a["label"], a["account"], a["stage"],
        {"sourceSecretArn": a["sourceSecretArn"], "versionId": a["sourceSecretVersion"],
         "kmsKeyArn": a["sourceKmsKeyArn"]}, a["owner"])
    require(a == expected, "Explicit allocation differs from the deterministic source names")
    require(len(a["brokerFunctionName"]) <= 64 and len(a["sourceFunctionArn"].rsplit(":", 1)[1]) <= 64)
    require(set(oauth) == {"clientId", "scope", "issuer", "authorizationEndpoint", "tokenEndpoint"})
    require(re.fullmatch(r"[a-z0-9]{1,128}", oauth["clientId"]))
    require(isinstance(oauth["scope"], str) and re.fullmatch(r"[A-Za-z0-9_.:/-]{1,256}", oauth["scope"]))
    require(re.fullmatch(r"https://cognito-idp\.eu-west-1\.amazonaws\.com/eu-west-1_[A-Za-z0-9]+",
                         oauth["issuer"]))
    token, authorize = urlsplit(oauth["tokenEndpoint"]), urlsplit(oauth["authorizationEndpoint"])
    require(token.scheme == authorize.scheme == "https" and token.hostname == authorize.hostname
            and isinstance(token.hostname, str)
            and re.fullmatch(r"[a-z0-9-]+\.auth\.eu-west-1\.amazoncognito\.com", token.hostname)
            and token.netloc == authorize.netloc == token.hostname
            and token.path == "/oauth2/token" and authorize.path == "/oauth2/authorize"
            and not any((token.query, token.fragment, authorize.query, authorize.fragment)))
    config = {k: a[k] for k in ("account", "region", "stage", "owner", "logicalResourceId",
                               "stackName", "sourceSecretArn", "sourceSecretVersion", "brokerFunctionName",
                               "ledgerTableName", "sourceRoleArn", "sourceFunctionArn")}
    config["oauth"] = oauth
    require(len(canonical(config).encode()) <= 3000)
    return a, config


def render(value, output):
    a, config = reviewed_input(value)
    output.mkdir(parents=True, exist_ok=False)
    files = {"foundation-template.json": foundation(a), "broker-granular-inline.json": policy(a),
             "broker-purpose.json": purpose_ceiling(a), "source-boundary-template.json": source_boundary(a),
             "broker-config.json": config}
    for name, data in files.items():
        # The config's exact canonical bytes are the Lambda environment/hash input.
        (output / name).write_text(canonical(data) if name == "broker-config.json"
                                  else json.dumps(data, sort_keys=True, indent=2) + "\n")
    here = Path(__file__).resolve().parent
    with zipfile.ZipFile(output / "broker.zip", "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in ("protocol.py", "runtime.py"):
            info = zipfile.ZipInfo(name, (2020, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, (here / name).read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    package = (output / "broker.zip").read_bytes()
    receipt = {"status": "OFFLINE_RENDER_ONLY_NATIVE_PROVISIONING_AND_ACCEPTANCE_HELD",
               "account": a["account"], "region": a["region"], "foundationStackName": a["foundationStackName"],
               "brokerConfigSha256": digest(config), "brokerCodeSha256": base64.b64encode(hashlib.sha256(package).digest()).decode(),
               "brokerPackageSha256": hashlib.sha256(package).hexdigest(),
               "newFoundationResources": 6, "nativeCalls": 0, "nativeWrites": 0,
               "actualPublishedBrokerVersionArn": None,
               "sourceBoundaryRequiresActualPublishedVersion": True}
    (output / "render-receipt.json").write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="Reviewed public allocation/OAuth JSON; no secrets")
    parser.add_argument("--output", type=Path, required=True, help="New output directory")
    args = parser.parse_args()
    render(json.loads(args.input.read_text()), args.output)


if __name__ == "__main__":
    main()
