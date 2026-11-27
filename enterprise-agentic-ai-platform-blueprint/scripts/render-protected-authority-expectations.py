#!/usr/bin/env python3
"""Bind installed-policy expectations to an approved management assembly.

Reads local JSON only. Supply resolved OU/root IDs for CloudFormation target
references. Output is a reviewable release record, not approval or deployment.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

TARGET = re.compile(r"^(?:\d{12}|ou-[a-z0-9]{4,32}-[a-z0-9]{8,32}|r-[a-z0-9]{4,32})$")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON keys are forbidden")
        result[key] = value
    return result


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(
        path.read_text(encoding="utf-8"), object_pairs_hook=unique_object
    )
    require(isinstance(value, dict), "input must be a JSON object")
    return value


def digest(value: Any) -> str:
    data = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def resolved_json(value: Any) -> bool:
    if isinstance(value, dict):
        return all(
            key != "Ref" and not key.startswith("Fn::") and resolved_json(child)
            for key, child in value.items()
        )
    if isinstance(value, list):
        return all(resolved_json(child) for child in value)
    return isinstance(value, (str, int, float, bool)) or value is None


def resolve_target(raw: Any, mapping: dict[str, Any]) -> str:
    if isinstance(raw, str):
        target = raw
    elif isinstance(raw, dict) and set(raw) == {"Fn::GetAtt"}:
        reference = raw["Fn::GetAtt"]
        require(
            isinstance(reference, list)
            and len(reference) == 2
            and reference[1] in {"Id", "RootId"},
            "unsupported target attribute",
        )
        target = mapping.get(reference[0])
    elif isinstance(raw, dict) and set(raw) == {"Ref"}:
        target = mapping.get(raw["Ref"])
    else:
        raise ValueError("unsupported or unresolved policy target")
    require(
        isinstance(target, str) and TARGET.fullmatch(target) is not None,
        "every target needs an exact resolved account, OU or root ID",
    )
    return target


def render(
    manifest: dict[str, Any], template: dict[str, Any], mapping: dict[str, Any]
) -> dict[str, Any]:
    require(
        manifest.get("schemaVersion") == 1, "a validated version 1 manifest is required"
    )
    governed = manifest.get("governedAccountIds")
    require(
        isinstance(governed, list)
        and bool(governed)
        and all(
            isinstance(account, str) and re.fullmatch(r"\d{12}", account)
            for account in governed
        )
        and len(set(governed)) == len(governed),
        "governed accounts must be exact and unique",
    )
    policies: list[dict[str, Any]] = []
    names: set[str] = set()
    authority_counts = {account: 0 for account in governed}
    resources = template.get("Resources")
    require(
        isinstance(resources, dict),
        "an approved CloudFormation management template is required",
    )
    for resource in resources.values():
        if resource.get("Type") != "AWS::Organizations::Policy":
            continue
        props = resource["Properties"]
        require(
            props.get("Type") == "SERVICE_CONTROL_POLICY",
            "only SCP expectations are supported",
        )
        name = props.get("Name")
        require(
            isinstance(name, str) and name not in names,
            "policy names must be literal and unique",
        )
        names.add(name)
        body = props["Content"]
        if isinstance(body, str):
            body = json.loads(body, object_pairs_hook=unique_object)
        require(
            isinstance(body, dict)
            and body.get("Version") == "2012-10-17"
            and resolved_json(body),
            "policy content must be resolved IAM JSON",
        )
        targets = [resolve_target(raw, mapping) for raw in props["TargetIds"]]
        require(
            bool(targets) and len(set(targets)) == len(targets),
            "policy targets must be nonempty and unique",
        )
        if name.startswith("AgenticAI-ProtectedAuthority-"):
            require(
                len(targets) == 1 and targets[0] in authority_counts,
                "authority protection must attach directly to one governed account",
            )
            statements = body.get("Statement")
            require(
                isinstance(statements, list)
                and bool(statements)
                and all(statement.get("Effect") == "Deny" for statement in statements),
                "authority protections must contain explicit denials",
            )
            require(
                len(json.dumps(body, separators=(",", ":"), ensure_ascii=False))
                <= 5000,
                "authority policy exceeds the compiler size limit",
            )
            authority_counts[targets[0]] += 1
        policies.append(
            {"name": name, "bodySha256": digest(body), "targetIds": sorted(targets)}
        )
    require(
        all(0 < count <= 9 for count in authority_counts.values()),
        "every governed account needs protections within the direct attachment quota",
    )
    return {
        "manifestSha256": digest(manifest),
        "approvedTemplateSha256": digest(template),
        "policies": sorted(policies, key=lambda policy: policy["name"]),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--template", required=True, type=Path)
    parser.add_argument("--target-map", type=Path)
    args = parser.parse_args()
    try:
        result = render(
            read_json(args.manifest),
            read_json(args.template),
            read_json(args.target_map) if args.target_map else {},
        )
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        print(f"Cannot render authority expectations: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
