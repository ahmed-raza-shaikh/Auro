"""
╔══════════════════════════════════════════════════════════════════════════════╗
║        Auro — Automated Cloud Compliance Engine                            ║
║        Module: tests/test_cis_checks.py                                   ║
║        Purpose: Unit tests for CIS check logic using moto + unittest.mock  ║
╚══════════════════════════════════════════════════════════════════════════════╝

Run with:
    pytest tests/ -v --tb=short
"""

from __future__ import annotations

import sys
import os
import json
import unittest
from unittest.mock import MagicMock, patch, call
from datetime import datetime, timezone

# Ensure the project root is on path (for local dev without install)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cis_checks import (
    CheckStatus,
    CheckFinding,
    check_root_mfa_and_usage,
    check_iam_password_policy,
    check_cloudtrail_configuration,
    check_s3_public_access,
    check_security_group_unrestricted_access,
    run_all_checks,
)


# ──────────────────────────────────────────────────────────────────────────────
# Test: Root MFA Check
# ──────────────────────────────────────────────────────────────────────────────

class TestCheckRootMFA(unittest.TestCase):

    def _make_credential_report_csv(self, mfa_active=True, key1_active=False):
        """Helper to generate a mock IAM credential report CSV."""
        return (
            "user,arn,user_creation_time,password_enabled,password_last_used,"
            "password_last_changed,password_next_rotation,mfa_active,"
            "access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,"
            "access_key_2_active,access_key_2_last_used_date\n"
            f"<root_account>,arn:aws:iam::123456789012:root,2020-01-01T00:00:00+00:00,"
            f"not_supported,2024-01-01T10:00:00+00:00,not_supported,not_supported,"
            f"{'true' if mfa_active else 'false'},"
            f"{'true' if key1_active else 'false'},2024-01-01T00:00:00+00:00,N/A,"
            f"false,N/A"
        ).encode("utf-8")

    @patch("cis_checks.boto3.client")
    def test_root_mfa_enabled_pass(self, mock_boto_client):
        """PASS when root MFA is enabled and no active access keys."""
        mock_iam = MagicMock()
        mock_boto_client.return_value = mock_iam

        mock_iam.get_account_summary.return_value = {
            "SummaryMap": {"AccountMFAEnabled": 1}
        }
        mock_iam.generate_credential_report.return_value = {"State": "COMPLETE"}
        mock_iam.get_credential_report.return_value = {
            "Content": self._make_credential_report_csv(mfa_active=True, key1_active=False)
        }

        result = check_root_mfa_and_usage()
        self.assertEqual(result.status, CheckStatus.PASS)
        self.assertIn("MFA is enabled", result.details)

    @patch("cis_checks.boto3.client")
    def test_root_mfa_disabled_fail(self, mock_boto_client):
        """FAIL when root MFA is not enabled."""
        mock_iam = MagicMock()
        mock_boto_client.return_value = mock_iam

        mock_iam.get_account_summary.return_value = {
            "SummaryMap": {"AccountMFAEnabled": 0}
        }
        mock_iam.generate_credential_report.return_value = {"State": "COMPLETE"}
        mock_iam.get_credential_report.return_value = {
            "Content": self._make_credential_report_csv(mfa_active=False, key1_active=False)
        }

        result = check_root_mfa_and_usage()
        self.assertEqual(result.status, CheckStatus.FAIL)
        self.assertIn("does NOT have MFA", result.details)

    @patch("cis_checks.boto3.client")
    def test_root_active_access_key_fail(self, mock_boto_client):
        """FAIL when root account has an active programmatic access key."""
        mock_iam = MagicMock()
        mock_boto_client.return_value = mock_iam

        mock_iam.get_account_summary.return_value = {
            "SummaryMap": {"AccountMFAEnabled": 1}
        }
        mock_iam.generate_credential_report.return_value = {"State": "COMPLETE"}
        mock_iam.get_credential_report.return_value = {
            "Content": self._make_credential_report_csv(mfa_active=True, key1_active=True)
        }

        result = check_root_mfa_and_usage()
        self.assertEqual(result.status, CheckStatus.FAIL)
        self.assertIn("programmatic access keys", result.details)


# ──────────────────────────────────────────────────────────────────────────────
# Test: IAM Password Policy
# ──────────────────────────────────────────────────────────────────────────────

class TestCheckIAMPasswordPolicy(unittest.TestCase):

    COMPLIANT_POLICY = {
        "MinimumPasswordLength":     14,
        "RequireUppercaseCharacters": True,
        "RequireLowercaseCharacters": True,
        "RequireNumbers":             True,
        "RequireSymbols":             True,
        "PasswordReusePrevention":    24,
        "MaxPasswordAge":             90,
    }

    @patch("cis_checks.boto3.client")
    def test_compliant_policy_pass(self, mock_boto_client):
        """PASS when all password policy attributes meet CIS requirements."""
        mock_iam = MagicMock()
        mock_boto_client.return_value = mock_iam
        mock_iam.get_account_password_policy.return_value = {
            "PasswordPolicy": self.COMPLIANT_POLICY
        }

        result = check_iam_password_policy()
        self.assertEqual(result.status, CheckStatus.PASS)
        self.assertIn("PASS", result.details)

    @patch("cis_checks.boto3.client")
    def test_short_min_length_fail(self, mock_boto_client):
        """FAIL when minimum password length is below 14."""
        mock_iam = MagicMock()
        mock_boto_client.return_value = mock_iam
        weak_policy = {**self.COMPLIANT_POLICY, "MinimumPasswordLength": 8}
        mock_iam.get_account_password_policy.return_value = {
            "PasswordPolicy": weak_policy
        }

        result = check_iam_password_policy()
        self.assertEqual(result.status, CheckStatus.FAIL)
        self.assertIn("MinimumPasswordLength=8", result.details)

    @patch("cis_checks.boto3.client")
    def test_no_policy_configured_fail(self, mock_boto_client):
        """FAIL when no password policy exists (NoSuchEntity)."""
        from botocore.exceptions import ClientError
        mock_iam = MagicMock()
        mock_boto_client.return_value = mock_iam
        mock_iam.get_account_password_policy.side_effect = ClientError(
            {"Error": {"Code": "NoSuchEntity", "Message": "No policy."}},
            "GetAccountPasswordPolicy",
        )

        result = check_iam_password_policy()
        self.assertEqual(result.status, CheckStatus.FAIL)
        self.assertIn("No IAM password policy", result.details)


# ──────────────────────────────────────────────────────────────────────────────
# Test: CloudTrail Configuration
# ──────────────────────────────────────────────────────────────────────────────

class TestCheckCloudTrail(unittest.TestCase):

    @patch("cis_checks.boto3.client")
    def test_compliant_multiregion_trail_pass(self, mock_boto_client):
        """PASS when a compliant multi-region trail exists."""
        mock_ct = MagicMock()
        mock_boto_client.return_value = mock_ct

        mock_ct.describe_trails.return_value = {"trailList": [{
            "Name": "my-trail",
            "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/my-trail",
            "IsMultiRegionTrail": True,
            "LogFileValidationEnabled": True,
        }]}
        mock_ct.get_trail_status.return_value = {"IsLogging": True}
        mock_ct.get_event_selectors.return_value = {"EventSelectors": [{
            "ReadWriteType": "All",
            "IncludeManagementEvents": True,
        }]}

        result = check_cloudtrail_configuration()
        self.assertEqual(result.status, CheckStatus.PASS)

    @patch("cis_checks.boto3.client")
    def test_no_trails_fail(self, mock_boto_client):
        """FAIL when no CloudTrail trails are found."""
        mock_ct = MagicMock()
        mock_boto_client.return_value = mock_ct
        mock_ct.describe_trails.return_value = {"trailList": []}

        result = check_cloudtrail_configuration()
        self.assertEqual(result.status, CheckStatus.FAIL)
        self.assertIn("No CloudTrail trails", result.details)

    @patch("cis_checks.boto3.client")
    def test_logging_disabled_fail(self, mock_boto_client):
        """FAIL when a trail exists but logging is disabled."""
        mock_ct = MagicMock()
        mock_boto_client.return_value = mock_ct

        mock_ct.describe_trails.return_value = {"trailList": [{
            "Name": "inactive-trail",
            "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/inactive-trail",
            "IsMultiRegionTrail": True,
            "LogFileValidationEnabled": True,
        }]}
        mock_ct.get_trail_status.return_value = {"IsLogging": False}
        mock_ct.get_event_selectors.return_value = {"EventSelectors": [{
            "ReadWriteType": "All",
            "IncludeManagementEvents": True,
        }]}

        result = check_cloudtrail_configuration()
        self.assertEqual(result.status, CheckStatus.FAIL)
        self.assertIn("logging is DISABLED", result.details)


# ──────────────────────────────────────────────────────────────────────────────
# Test: S3 Public Access
# ──────────────────────────────────────────────────────────────────────────────

class TestCheckS3PublicAccess(unittest.TestCase):

    @patch("cis_checks.boto3.client")
    def test_all_buckets_private_pass(self, mock_boto_client):
        """PASS when all buckets have public access fully blocked."""
        mock_s3 = MagicMock()
        mock_boto_client.return_value = mock_s3

        mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "my-private-bucket"}]}
        mock_s3.get_bucket_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }
        from botocore.exceptions import ClientError
        mock_s3.get_bucket_policy_status.side_effect = ClientError(
            {"Error": {"Code": "NoSuchBucketPolicy", "Message": ""}},
            "GetBucketPolicyStatus",
        )
        mock_s3.get_bucket_acl.return_value = {"Grants": []}

        result = check_s3_public_access()
        self.assertEqual(result.status, CheckStatus.PASS)

    @patch("cis_checks.boto3.client")
    def test_public_bucket_fail(self, mock_boto_client):
        """FAIL when a bucket does not have BlockPublicAcls set."""
        mock_s3 = MagicMock()
        mock_boto_client.return_value = mock_s3

        mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "public-bucket"}]}
        mock_s3.get_bucket_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": False,  # Non-compliant
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }
        from botocore.exceptions import ClientError
        mock_s3.get_bucket_policy_status.side_effect = ClientError(
            {"Error": {"Code": "NoSuchBucketPolicy", "Message": ""}},
            "GetBucketPolicyStatus",
        )
        mock_s3.get_bucket_acl.return_value = {"Grants": []}

        result = check_s3_public_access()
        self.assertEqual(result.status, CheckStatus.FAIL)
        self.assertIn("public-bucket", result.resources)


# ──────────────────────────────────────────────────────────────────────────────
# Test: Security Group Unrestricted Access
# ──────────────────────────────────────────────────────────────────────────────

class TestCheckSecurityGroups(unittest.TestCase):

    @patch("cis_checks.boto3.client")
    def test_no_open_ports_pass(self, mock_boto_client):
        """PASS when no security group exposes port 22 or 3389 to the world."""
        mock_ec2 = MagicMock()
        mock_boto_client.return_value = mock_ec2

        mock_paginator = MagicMock()
        mock_ec2.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = iter([{
            "SecurityGroups": [{
                "GroupId":   "sg-secure",
                "GroupName": "my-sg",
                "IpPermissions": [{
                    "IpProtocol": "tcp",
                    "FromPort":   22,
                    "ToPort":     22,
                    "IpRanges":   [{"CidrIp": "10.0.0.0/8"}],   # Private CIDR only
                    "Ipv6Ranges": [],
                }],
            }]
        }])

        result = check_security_group_unrestricted_access()
        self.assertEqual(result.status, CheckStatus.PASS)

    @patch("cis_checks.boto3.client")
    def test_open_ssh_to_world_fail(self, mock_boto_client):
        """FAIL when port 22 is open to 0.0.0.0/0."""
        mock_ec2 = MagicMock()
        mock_boto_client.return_value = mock_ec2

        mock_paginator = MagicMock()
        mock_ec2.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = iter([{
            "SecurityGroups": [{
                "GroupId":   "sg-open-ssh",
                "GroupName": "open-sg",
                "IpPermissions": [{
                    "IpProtocol": "tcp",
                    "FromPort":   22,
                    "ToPort":     22,
                    "IpRanges":   [{"CidrIp": "0.0.0.0/0"}],   # World-open
                    "Ipv6Ranges": [],
                }],
            }]
        }])

        result = check_security_group_unrestricted_access()
        self.assertEqual(result.status, CheckStatus.FAIL)
        self.assertIn("sg-open-ssh", result.resources)


# ──────────────────────────────────────────────────────────────────────────────
# Test: run_all_checks integration
# ──────────────────────────────────────────────────────────────────────────────

class TestRunAllChecks(unittest.TestCase):

    @patch("cis_checks.check_security_group_unrestricted_access")
    @patch("cis_checks.check_s3_public_access")
    @patch("cis_checks.check_cloudtrail_configuration")
    @patch("cis_checks.check_iam_password_policy")
    @patch("cis_checks.check_root_mfa_and_usage")
    def test_all_checks_executed(self, m_root, m_pw, m_ct, m_s3, m_sg):
        """run_all_checks() must call every check function exactly once."""
        dummy = CheckFinding(
            check_id="TEST", title="Test", description="Test",
            status=CheckStatus.PASS, details="ok"
        )
        for m in [m_root, m_pw, m_ct, m_s3, m_sg]:
            m.return_value = dummy

        findings = run_all_checks()

        self.assertEqual(len(findings), 5)
        m_root.assert_called_once()
        m_pw.assert_called_once()
        m_ct.assert_called_once()
        m_s3.assert_called_once()
        m_sg.assert_called_once()

    @patch("cis_checks.check_security_group_unrestricted_access")
    @patch("cis_checks.check_s3_public_access")
    @patch("cis_checks.check_cloudtrail_configuration")
    @patch("cis_checks.check_iam_password_policy")
    @patch("cis_checks.check_root_mfa_and_usage")
    def test_exception_in_one_check_does_not_abort(self, m_root, m_pw, m_ct, m_s3, m_sg):
        """A crash in one check must be caught; remaining checks must still run."""
        m_root.side_effect = RuntimeError("Simulated failure")
        dummy = CheckFinding(
            check_id="TEST", title="Test", description="Test",
            status=CheckStatus.PASS, details="ok"
        )
        for m in [m_pw, m_ct, m_s3, m_sg]:
            m.return_value = dummy

        findings = run_all_checks()

        # 5 results: 1 ERROR (from crash) + 4 PASSes
        self.assertEqual(len(findings), 5)
        self.assertEqual(findings[0].status, CheckStatus.ERROR)
        self.assertEqual(sum(1 for f in findings if f.status == CheckStatus.PASS), 4)


if __name__ == "__main__":
    unittest.main(verbosity=2)
