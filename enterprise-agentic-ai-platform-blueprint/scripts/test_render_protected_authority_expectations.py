"""Attack/control checks for approved-assembly expectation generation."""

from __future__ import annotations

import copy
import importlib.util
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "authority_expectations",
    Path(__file__).with_name("render-protected-authority-expectations.py"),
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ExpectationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = {"schemaVersion": 1, "governedAccountIds": ["333333333333"]}
        self.body = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Deny", "Action": "iam:DeleteRole", "Resource": "*"}
            ],
        }
        self.template = {
            "Resources": {
                "Protection": {
                    "Type": "AWS::Organizations::Policy",
                    "Properties": {
                        "Name": "AgenticAI-ProtectedAuthority-333333333333-1",
                        "Type": "SERVICE_CONTROL_POLICY",
                        "Content": self.body,
                        "TargetIds": ["333333333333"],
                    },
                },
                "Business": {
                    "Type": "AWS::Organizations::Policy",
                    "Properties": {
                        "Name": "AgenticAI-SCP-09-GatewayMutationLockdown",
                        "Type": "SERVICE_CONTROL_POLICY",
                        "Content": self.body,
                        "TargetIds": [{"Fn::GetAtt": ["Sandbox", "Id"]}],
                    },
                },
            },
        }
        self.mapping = {"Sandbox": "ou-ab12-12345678"}

    def render(self):
        return MODULE.render(self.manifest, self.template, self.mapping)

    def test_exact_accounts_and_resolved_ou_keep_all_policies(self):
        result = self.render()
        self.assertEqual(result["manifestSha256"], MODULE.digest(self.manifest))
        self.assertEqual(len(result["policies"]), 2)
        self.assertEqual(result["policies"][1]["bodySha256"], MODULE.digest(self.body))

    def test_hashes_bind_content_changes(self):
        before = self.render()
        self.body["Statement"][0]["Action"] = "iam:PutRolePolicy"
        after = self.render()
        self.assertNotEqual(
            before["approvedTemplateSha256"], after["approvedTemplateSha256"]
        )
        self.assertNotEqual(
            before["policies"][0]["bodySha256"], after["policies"][0]["bodySha256"]
        )

    def test_missing_governed_account_guard_fails(self):
        self.manifest["governedAccountIds"].append("444444444444")
        with self.assertRaisesRegex(ValueError, "every governed account"):
            self.render()

    def test_unresolved_target_fails(self):
        self.mapping.clear()
        with self.assertRaisesRegex(ValueError, "exact resolved"):
            self.render()

    def test_wildcard_and_wrong_account_targets_fail(self):
        for target in ["*", "33333333333*", "444444444444", "ou-ab12-12345678"]:
            with self.subTest(target=target):
                self.template["Resources"]["Protection"]["Properties"]["TargetIds"] = [
                    target
                ]
                with self.assertRaises(ValueError):
                    self.render()

    def test_duplicate_policy_names_fail(self):
        self.template["Resources"]["Business"]["Properties"]["Name"] = self.template[
            "Resources"
        ]["Protection"]["Properties"]["Name"]
        with self.assertRaisesRegex(ValueError, "unique"):
            self.render()

    def test_allow_or_empty_protection_fails(self):
        for statements in [[], [{"Effect": "Allow"}]]:
            with self.subTest(statements=statements):
                self.body["Statement"] = statements
                with self.assertRaisesRegex(ValueError, "explicit denials"):
                    self.render()

    def test_attachment_quota_fails(self):
        original = self.template["Resources"]["Protection"]
        for index in range(2, 11):
            item = copy.deepcopy(original)
            item["Properties"]["Name"] = (
                f"AgenticAI-ProtectedAuthority-333333333333-{index}"
            )
            self.template["Resources"][f"Protection{index}"] = item
        with self.assertRaisesRegex(ValueError, "attachment quota"):
            self.render()

    def test_reference_target_and_string_content_are_supported(self):
        self.template["Resources"]["Business"]["Properties"]["TargetIds"] = [
            {"Ref": "Sandbox"}
        ]
        self.template["Resources"]["Protection"]["Properties"]["Content"] = (
            MODULE.json.dumps(self.body)
        )
        self.assertEqual(len(self.render()["policies"]), 2)

    def test_unknown_intrinsic_fails(self):
        self.template["Resources"]["Business"]["Properties"]["TargetIds"] = [
            {"Fn::Sub": "${Scope}"}
        ]
        with self.assertRaisesRegex(ValueError, "unsupported"):
            self.render()

    def test_unresolved_policy_content_fails(self):
        self.body["Statement"][0]["Resource"] = {"Fn::Sub": "${RoleArn}"}
        with self.assertRaisesRegex(ValueError, "resolved IAM JSON"):
            self.render()

    def test_duplicate_input_json_keys_fail(self):
        with self.assertRaisesRegex(ValueError, "duplicate JSON keys"):
            MODULE.unique_object([("schemaVersion", 1), ("schemaVersion", 2)])


if __name__ == "__main__":
    unittest.main()
