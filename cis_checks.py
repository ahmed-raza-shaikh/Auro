"""
╔══════════════════════════════════════════════════════════════════════════════╗
║        Auro — Automated Cloud Compliance Engine                            ║
║        Module: cis_checks.py                                               ║
║        Purpose: Modular CIS Benchmark v1.4 check implementations          ║
║                 using pure Boto3 — no AWS Config Rules required.           ║
║                                                                            ║
║  CIS Controls Implemented:                                                 ║
║    1.1  — Avoid the use of the root account (MFA enabled check)            ║
║    1.8  — Ensure IAM password policy requires minimum length of 14+        ║
║    2.1  — Ensure CloudTrail is enabled in all regions                      ║
║    2.2  — Ensure CloudTrail log file validation is enabled                 ║
║    3.x  — S3 buckets do not allow public access                            ║
║    5.1  — Ensure no security groups allow unrestricted ingress to :22/:3389║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import base64
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import List

import boto3
from botocore.exceptions import ClientError

# ──────────────────────────────────────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────────────────────────────────────
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


# ──────────────────────────────────────────────────────────────────────────────
# Domain Models
# ──────────────────────────────────────────────────────────────────────────────

class CheckStatus(str, Enum):
    PASS    = "PASS"
    FAIL    = "FAIL"
    ERROR   = "ERROR"
    WARNING = "WARNING"


@dataclass
class CheckFinding:
    """
    Represents the result of a single CIS compliance check.
    Each finding maps 1-to-1 to a row in the generated PDF report.
    """
    check_id:    str                        # e.g. "CIS-1.1"
    title:       str                        # Short human-readable title
    description: str                        # What the check evaluates
    status:      CheckStatus                # PASS | FAIL | ERROR | WARNING
    details:     str          = ""          # Supporting context / remediation hint
    resources:   List[str]    = field(default_factory=list)  # Affected resource IDs/ARNs
    severity:    str          = "MEDIUM"    # CRITICAL | HIGH | MEDIUM | LOW


# ──────────────────────────────────────────────────────────────────────────────
# Helper: safe Boto3 client factory
# ──────────────────────────────────────────────────────────────────────────────

def _client(service: str, region: str = "us-east-1"):
    """Return a Boto3 client with standardised retries."""
    return boto3.client(
        service,
        region_name=region,
        config=boto3.session.Config(retries={"max_attempts": 3, "mode": "standard"}),
    )


# ══════════════════════════════════════════════════════════════════════════════
# CHECK 1  ▸  CIS 1.1 / 1.5 — Root Account MFA & Last Activity
# CIS Benchmark v1.4 | Section 1.1, 1.5
# ══════════════════════════════════════════════════════════════════════════════

def check_root_mfa_and_usage() -> CheckFinding:
    """
    CIS 1.1 — Avoid using the root account.
    CIS 1.5 — Enable MFA for the root account.

    Strategy:
      1. Call iam:GetAccountSummary → AccountMFAEnabled flag.
      2. Generate + fetch the IAM Credential Report to detect recent root usage.
         The credential report is cached by AWS for up to 4 hours, so we
         trigger generation and poll until COMPLETE (usually < 5 s).
    """
    iam = _client("iam")
    findings = []
    status   = CheckStatus.PASS
    details_parts: List[str] = []

    # ── 1a. MFA enabled on root ──────────────────────────────────────────────
    try:
        summary = iam.get_account_summary()["SummaryMap"]
        mfa_active = summary.get("AccountMFAEnabled", 0)

        if mfa_active != 1:
            status = CheckStatus.FAIL
            details_parts.append(
                "FAIL: Root account does NOT have MFA enabled. "
                "Remediation: Navigate to IAM → Security credentials → "
                "Activate MFA for root user."
            )
        else:
            details_parts.append("PASS: Root account MFA is enabled.")
    except ClientError as exc:
        logger.warning("check_root_mfa — GetAccountSummary error: %s", exc)
        return CheckFinding(
            check_id="CIS-1.1/1.5",
            title="Root Account MFA & Usage",
            description="Ensure root MFA is enabled and root is not used operationally.",
            status=CheckStatus.ERROR,
            details=f"Unable to retrieve account summary: {exc}",
            severity="CRITICAL",
        )

    # ── 1b. Recent root usage via credential report ──────────────────────────
    try:
        # Trigger generation; if already fresh, AWS returns COMPLETE immediately
        for _ in range(10):
            resp = iam.generate_credential_report()
            if resp["State"] == "COMPLETE":
                break
            time.sleep(2)

        report_resp = iam.get_credential_report()
        report_csv  = report_resp["Content"]

        # Content is bytes (base64 inside SDK already decoded for us)
        if isinstance(report_csv, (bytes, bytearray)):
            report_csv = report_csv.decode("utf-8")

        lines = report_csv.strip().splitlines()
        headers = lines[0].split(",")

        for line in lines[1:]:
            cols    = line.split(",")
            row     = dict(zip(headers, cols))
            user    = row.get("user", "")

            if user != "<root_account>":
                continue

            last_used = row.get("password_last_used", "N/A")
            access_1  = row.get("access_key_1_last_used_date", "N/A")
            access_2  = row.get("access_key_2_last_used_date", "N/A")

            # Flag active root access keys as a CRITICAL issue
            key1_active = row.get("access_key_1_active", "false").lower() == "true"
            key2_active = row.get("access_key_2_active", "false").lower() == "true"

            if key1_active or key2_active:
                status = CheckStatus.FAIL
                details_parts.append(
                    f"CRITICAL: Root account has active programmatic access keys. "
                    f"Key1 active={key1_active}, Key2 active={key2_active}. "
                    "Remediation: Delete root access keys immediately."
                )
            else:
                details_parts.append("PASS: No active root access keys found.")

            details_parts.append(
                f"Root last console login: {last_used} | "
                f"Key1 last used: {access_1} | Key2 last used: {access_2}"
            )

    except ClientError as exc:
        logger.warning("check_root_mfa — CredentialReport error: %s", exc)
        details_parts.append(f"WARNING: Could not fetch credential report: {exc}")

    return CheckFinding(
        check_id="CIS-1.1/1.5",
        title="Root Account MFA & Usage",
        description=(
            "Ensures the root account has MFA enabled and is not used for "
            "day-to-day operations. Active root access keys are flagged as CRITICAL."
        ),
        status=status,
        details=" | ".join(details_parts),
        severity="CRITICAL",
    )


# ══════════════════════════════════════════════════════════════════════════════
# CHECK 2  ▸  CIS 1.8 — IAM Account Password Policy
# CIS Benchmark v1.4 | Section 1.8–1.11
# ══════════════════════════════════════════════════════════════════════════════

def check_iam_password_policy() -> CheckFinding:
    """
    CIS 1.8 — IAM account password policy must enforce:
      • Minimum password length ≥ 14
      • Require uppercase, lowercase, numbers, symbols
      • Prohibit password reuse (≥ 24 generations)
      • Maximum password age ≤ 90 days
    """
    iam = _client("iam")
    failures: List[str] = []
    status = CheckStatus.PASS

    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
    except ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        if error_code == "NoSuchEntity":
            return CheckFinding(
                check_id="CIS-1.8",
                title="IAM Password Policy",
                description="Account password policy meets CIS complexity requirements.",
                status=CheckStatus.FAIL,
                details=(
                    "FAIL: No IAM password policy is configured for this account. "
                    "Remediation: Apply a compliant password policy via the IAM console "
                    "or using aws iam update-account-password-policy."
                ),
                severity="HIGH",
            )
        return CheckFinding(
            check_id="CIS-1.8",
            title="IAM Password Policy",
            description="Account password policy meets CIS complexity requirements.",
            status=CheckStatus.ERROR,
            details=f"ERROR: Unexpected API error — {exc}",
            severity="HIGH",
        )

    # ── Policy attribute checks ──────────────────────────────────────────────
    min_len = policy.get("MinimumPasswordLength", 0)
    if min_len < 14:
        failures.append(f"MinimumPasswordLength={min_len} (required ≥ 14)")

    if not policy.get("RequireUppercaseCharacters", False):
        failures.append("RequireUppercaseCharacters=False (required True)")

    if not policy.get("RequireLowercaseCharacters", False):
        failures.append("RequireLowercaseCharacters=False (required True)")

    if not policy.get("RequireNumbers", False):
        failures.append("RequireNumbers=False (required True)")

    if not policy.get("RequireSymbols", False):
        failures.append("RequireSymbols=False (required True)")

    reuse_prevention = policy.get("PasswordReusePrevention", 0)
    if reuse_prevention < 24:
        failures.append(f"PasswordReusePrevention={reuse_prevention} (required ≥ 24)")

    max_age = policy.get("MaxPasswordAge", 9999)
    if max_age > 90:
        failures.append(f"MaxPasswordAge={max_age} days (required ≤ 90)")

    if failures:
        status = CheckStatus.FAIL
        detail_str = (
            "FAIL: Password policy violates CIS benchmarks. "
            "Non-compliant settings: " + "; ".join(failures) + ". "
            "Remediation: Update via IAM → Account settings → Password policy."
        )
    else:
        detail_str = (
            f"PASS: Password policy is compliant. "
            f"MinLen={min_len}, MaxAge={max_age} days, "
            f"ReusePrevent={reuse_prevention} generations."
        )

    return CheckFinding(
        check_id="CIS-1.8",
        title="IAM Password Policy",
        description=(
            "Validates that the IAM account password policy enforces minimum "
            "length ≥14, complexity requirements, reuse prevention ≥24, "
            "and maximum age ≤90 days."
        ),
        status=status,
        details=detail_str,
        severity="HIGH",
    )


# ══════════════════════════════════════════════════════════════════════════════
# CHECK 3  ▸  CIS 3.1 / 3.2 — CloudTrail Enabled & Log Validation
# CIS Benchmark v1.4 | Section 3.1, 3.2
# ══════════════════════════════════════════════════════════════════════════════

def check_cloudtrail_configuration() -> CheckFinding:
    """
    CIS 3.1 — Ensure CloudTrail is enabled in all regions.
    CIS 3.2 — Ensure CloudTrail log file validation is enabled.

    A compliant trail must be:
      • Multi-region (IsMultiRegionTrail=True)
      • Actively logging (IsLogging=True)
      • Log file validation enabled (LogFileValidationEnabled=True)
      • Management events logged (read + write)
    """
    ct = _client("cloudtrail")
    failures: List[str] = []
    status   = CheckStatus.PASS
    affected: List[str] = []

    try:
        trails_resp = ct.describe_trails(includeShadowTrails=False)
        trails      = trails_resp.get("trailList", [])
    except ClientError as exc:
        return CheckFinding(
            check_id="CIS-3.1/3.2",
            title="CloudTrail Enabled & Log Validation",
            description="Ensures CloudTrail is active, multi-region, with log file validation.",
            status=CheckStatus.ERROR,
            details=f"ERROR: Unable to describe CloudTrail trails — {exc}",
            severity="HIGH",
        )

    if not trails:
        return CheckFinding(
            check_id="CIS-3.1/3.2",
            title="CloudTrail Enabled & Log Validation",
            description="Ensures CloudTrail is active, multi-region, with log file validation.",
            status=CheckStatus.FAIL,
            details=(
                "FAIL: No CloudTrail trails found in this account/region. "
                "Remediation: Create a multi-region trail in CloudTrail → Trails → Create trail."
            ),
            severity="HIGH",
        )

    has_compliant_multiregion_trail = False

    for trail in trails:
        trail_arn  = trail.get("TrailARN", "Unknown")
        trail_name = trail.get("Name", "Unknown")

        is_multiregion = trail.get("IsMultiRegionTrail", False)
        log_validation = trail.get("LogFileValidationEnabled", False)

        # ── Check logging status ─────────────────────────────────────────────
        try:
            status_resp = ct.get_trail_status(Name=trail_arn)
            is_logging  = status_resp.get("IsLogging", False)
        except ClientError as exc:
            logger.warning("Could not get trail status for %s: %s", trail_arn, exc)
            is_logging = False

        # ── Check management event selectors ─────────────────────────────────
        try:
            selectors_resp = ct.get_event_selectors(TrailName=trail_arn)
            event_selectors = selectors_resp.get("EventSelectors", [])
            mgmt_read_write = any(
                s.get("ReadWriteType") in ("All", "ReadOnly", "WriteOnly")
                and s.get("IncludeManagementEvents", False)
                for s in event_selectors
            )
        except ClientError:
            mgmt_read_write = False

        trail_issues: List[str] = []

        if not is_multiregion:
            trail_issues.append("not multi-region")
        if not is_logging:
            trail_issues.append("logging is DISABLED")
        if not log_validation:
            trail_issues.append("log file validation disabled")
        if not mgmt_read_write:
            trail_issues.append("management events not captured")

        if trail_issues:
            failures.append(f"Trail '{trail_name}': {', '.join(trail_issues)}")
            affected.append(trail_arn)
        elif is_multiregion:
            # At least one compliant multi-region trail exists → account is covered
            has_compliant_multiregion_trail = True

    if failures:
        status = CheckStatus.FAIL
        detail_str = (
            "FAIL: Non-compliant trail(s) detected. Issues: "
            + " | ".join(failures)
            + " Remediation: Edit trail settings in CloudTrail console."
        )
    elif not has_compliant_multiregion_trail:
        status = CheckStatus.FAIL
        detail_str = (
            "FAIL: No multi-region CloudTrail trail found. "
            "Remediation: Enable IsMultiRegionTrail on an existing trail."
        )
    else:
        detail_str = (
            f"PASS: {len(trails)} trail(s) evaluated. "
            "Multi-region, logging, and log validation are all enabled."
        )

    return CheckFinding(
        check_id="CIS-3.1/3.2",
        title="CloudTrail Enabled & Log Validation",
        description=(
            "Verifies at least one CloudTrail trail is multi-region, actively "
            "logging, has log file integrity validation enabled, and captures "
            "management events."
        ),
        status=status,
        details=detail_str,
        resources=affected,
        severity="HIGH",
    )


# ══════════════════════════════════════════════════════════════════════════════
# CHECK 4  ▸  CIS 5.2 — S3 Bucket Public Access Block
# CIS Benchmark v1.4 | Section 2.1.2, 2.1.5
# ══════════════════════════════════════════════════════════════════════════════

def check_s3_public_access() -> CheckFinding:
    """
    CIS 2.1.2 — Ensure S3 bucket public access block is enabled at account level.
    CIS 2.1.5 — Ensure S3 buckets are not publicly accessible.

    Strategy (defence in depth):
      1. Evaluate per-bucket S3 Public Access Block configuration.
         All four flags must be True: BlockPublicAcls, IgnorePublicAcls,
         BlockPublicPolicy, RestrictPublicBuckets.
      2. Check bucket policy status (PolicyStatus.IsPublic).
      3. Check bucket ACL for public grants (AllUsers / AuthenticatedUsers).
    """
    s3 = _client("s3")
    affected_buckets: List[str] = []
    checked          = 0
    status           = CheckStatus.PASS
    detail_lines:    List[str] = []

    try:
        buckets = s3.list_all_my_buckets() if False else s3.list_buckets()
        bucket_list = buckets.get("Buckets", [])
    except ClientError as exc:
        return CheckFinding(
            check_id="CIS-2.1.2/2.1.5",
            title="S3 Bucket Public Access",
            description="Ensures S3 buckets do not allow unrestricted public access.",
            status=CheckStatus.ERROR,
            details=f"ERROR: Unable to list S3 buckets — {exc}",
            severity="CRITICAL",
        )

    for bucket in bucket_list:
        bucket_name = bucket["Name"]
        checked    += 1
        bucket_issues: List[str] = []

        # ── Public Access Block ───────────────────────────────────────────────
        try:
            pab = s3.get_bucket_public_access_block(Bucket=bucket_name)
            config = pab.get("PublicAccessBlockConfiguration", {})

            required_flags = [
                "BlockPublicAcls",
                "IgnorePublicAcls",
                "BlockPublicPolicy",
                "RestrictPublicBuckets",
            ]
            for flag in required_flags:
                if not config.get(flag, False):
                    bucket_issues.append(f"{flag}=False")

        except ClientError as exc:
            err_code = exc.response["Error"]["Code"]
            if err_code == "NoSuchPublicAccessBlockConfiguration":
                # No block config at all — fully public-capable
                bucket_issues.append("No PublicAccessBlockConfiguration set")
            else:
                logger.warning("S3 PAB check failed for %s: %s", bucket_name, exc)

        # ── Policy Status (is the bucket policy granting public access?) ──────
        try:
            ps = s3.get_bucket_policy_status(Bucket=bucket_name)
            if ps.get("PolicyStatus", {}).get("IsPublic", False):
                bucket_issues.append("Bucket policy grants public access")
        except ClientError as exc:
            err_code = exc.response["Error"]["Code"]
            if err_code not in ("NoSuchBucketPolicy", "NoSuchBucket"):
                logger.warning("S3 policy status check failed for %s: %s", bucket_name, exc)

        # ── ACL Check ─────────────────────────────────────────────────────────
        try:
            acl = s3.get_bucket_acl(Bucket=bucket_name)
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                uri     = grantee.get("URI", "")
                if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                    bucket_issues.append(f"ACL grants public access to {uri.split('/')[-1]}")
        except ClientError as exc:
            logger.warning("S3 ACL check failed for %s: %s", bucket_name, exc)

        if bucket_issues:
            affected_buckets.append(bucket_name)
            detail_lines.append(
                f"  • {bucket_name}: {'; '.join(bucket_issues)}"
            )

    if affected_buckets:
        status = CheckStatus.FAIL
        summary = (
            f"FAIL: {len(affected_buckets)} of {checked} bucket(s) have public access issues:\n"
            + "\n".join(detail_lines)
            + "\nRemediation: Enable S3 Block Public Access at account and bucket level."
        )
    else:
        summary = (
            f"PASS: All {checked} S3 bucket(s) have public access properly restricted."
        )

    return CheckFinding(
        check_id="CIS-2.1.2/2.1.5",
        title="S3 Bucket Public Access",
        description=(
            "Evaluates every S3 bucket for: (1) Public Access Block configuration "
            "(all 4 flags), (2) public-granting bucket policies, and (3) ACLs "
            "granting access to AllUsers or AuthenticatedUsers."
        ),
        status=status,
        details=summary,
        resources=affected_buckets,
        severity="CRITICAL",
    )


# ══════════════════════════════════════════════════════════════════════════════
# CHECK 5  ▸  CIS 5.2 — Unrestricted SSH/RDP via Security Groups
# CIS Benchmark v1.4 | Section 5.2, 5.3
# ══════════════════════════════════════════════════════════════════════════════

def check_security_group_unrestricted_access() -> CheckFinding:
    """
    CIS 5.2 — Ensure no security groups allow unrestricted ingress on port 22 (SSH).
    CIS 5.3 — Ensure no security groups allow unrestricted ingress on port 3389 (RDP).

    'Unrestricted' = source CIDR is 0.0.0.0/0 (IPv4) or ::/0 (IPv6).
    """
    ec2 = _client("ec2")
    affected_sgs: List[str] = []
    detail_lines: List[str] = []
    status = CheckStatus.PASS

    SENSITIVE_PORTS = {22: "SSH", 3389: "RDP"}

    try:
        paginator = ec2.get_paginator("describe_security_groups")
        pages     = paginator.paginate()
    except ClientError as exc:
        return CheckFinding(
            check_id="CIS-5.2/5.3",
            title="Unrestricted SSH/RDP in Security Groups",
            description="Ensures no security group allows unrestricted ingress on port 22/3389.",
            status=CheckStatus.ERROR,
            details=f"ERROR: Unable to describe security groups — {exc}",
            severity="HIGH",
        )

    total_sgs = 0

    for page in pages:
        for sg in page.get("SecurityGroups", []):
            total_sgs += 1
            sg_id      = sg.get("GroupId", "Unknown")
            sg_name    = sg.get("GroupName", "Unknown")
            sg_issues: List[str] = []

            for rule in sg.get("IpPermissions", []):
                from_port = rule.get("FromPort", -1)
                to_port   = rule.get("ToPort",   -1)
                protocol  = rule.get("IpProtocol", "")

                # tcp or -1 (all traffic)
                if protocol not in ("-1", "tcp"):
                    continue

                for port, service in SENSITIVE_PORTS.items():
                    # Port falls within the rule's range
                    port_in_range = (
                        protocol == "-1"
                        or (from_port <= port <= to_port)
                    )

                    if not port_in_range:
                        continue

                    # IPv4 open to the world
                    open_ipv4 = any(
                        r.get("CidrIp") == "0.0.0.0/0"
                        for r in rule.get("IpRanges", [])
                    )
                    # IPv6 open to the world
                    open_ipv6 = any(
                        r.get("CidrIpv6") == "::/0"
                        for r in rule.get("Ipv6Ranges", [])
                    )

                    if open_ipv4 or open_ipv6:
                        sources = []
                        if open_ipv4: sources.append("0.0.0.0/0")
                        if open_ipv6: sources.append("::/0")
                        sg_issues.append(
                            f"Port {port} ({service}) open to {', '.join(sources)}"
                        )

            if sg_issues:
                affected_sgs.append(sg_id)
                detail_lines.append(
                    f"  • {sg_id} ({sg_name}): {'; '.join(sg_issues)}"
                )

    if affected_sgs:
        status = CheckStatus.FAIL
        summary = (
            f"FAIL: {len(affected_sgs)} of {total_sgs} security group(s) expose "
            f"sensitive ports to the internet:\n"
            + "\n".join(detail_lines)
            + "\nRemediation: Restrict ingress rules to known IP ranges or VPN CIDRs."
        )
    else:
        summary = (
            f"PASS: All {total_sgs} security group(s) evaluated. "
            "No unrestricted SSH (22) or RDP (3389) ingress detected."
        )

    return CheckFinding(
        check_id="CIS-5.2/5.3",
        title="Unrestricted SSH/RDP in Security Groups",
        description=(
            "Scans all EC2 security groups for inbound rules permitting unrestricted "
            "access (0.0.0.0/0 or ::/0) on port 22 (SSH) or 3389 (RDP)."
        ),
        status=status,
        details=summary,
        resources=affected_sgs,
        severity="HIGH",
    )


# ──────────────────────────────────────────────────────────────────────────────
# Public API: run all checks and return consolidated findings
# ──────────────────────────────────────────────────────────────────────────────

def run_all_checks() -> List[CheckFinding]:
    """
    Execute all CIS checks in sequence and return a list of CheckFinding objects.

    Returns:
        List[CheckFinding]: Results for every implemented check, in order.
    """
    logger.info("Starting CIS Benchmark check suite (5 checks)...")

    check_functions = [
        check_root_mfa_and_usage,
        check_iam_password_policy,
        check_cloudtrail_configuration,
        check_s3_public_access,
        check_security_group_unrestricted_access,
    ]

    findings: List[CheckFinding] = []

    for fn in check_functions:
        logger.info("Running check: %s", fn.__name__)
        try:
            result = fn()
            findings.append(result)
            logger.info(
                "  [%s] %s — %s", result.status.value, result.check_id, result.title
            )
        except Exception as exc:
            # Defensive catch: a single broken check must not abort the entire run
            logger.error("Unhandled exception in %s: %s", fn.__name__, exc, exc_info=True)
            findings.append(CheckFinding(
                check_id="UNKNOWN",
                title=fn.__name__,
                description="Check execution failed unexpectedly.",
                status=CheckStatus.ERROR,
                details=str(exc),
            ))

    logger.info(
        "Check suite complete. PASS=%d FAIL=%d ERROR=%d",
        sum(1 for f in findings if f.status == CheckStatus.PASS),
        sum(1 for f in findings if f.status == CheckStatus.FAIL),
        sum(1 for f in findings if f.status == CheckStatus.ERROR),
    )

    return findings
