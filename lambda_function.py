"""
╔══════════════════════════════════════════════════════════════════════════════╗
║        Auro — Automated Cloud Compliance Engine                            ║
║        Module: lambda_function.py                                          ║
║        Purpose: AWS Lambda entry point. Orchestrates CIS checks,           ║
║                 PDF generation, S3 upload, and Slack notification.         ║
║                                                                            ║
║  Trigger:   Amazon EventBridge (scheduled rule — cron daily @ 06:00 UTC)  ║
║  Runtime:   Python 3.12                                                    ║
║  Memory:    256 MB (ReportLab requires ~80 MB heap)                       ║
║  Timeout:   300 seconds                                                    ║
╚══════════════════════════════════════════════════════════════════════════════╝

Environment Variables (set in Lambda console or Terraform):
  SLACK_WEBHOOK_URL     — Incoming Webhook URL for compliance notifications
  S3_REPORTS_BUCKET     — S3 bucket name for persisting PDF reports
  AWS_REGION            — Injected automatically by Lambda runtime
  LOG_LEVEL             — Optional: DEBUG | INFO | WARNING (default: INFO)
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import boto3
import requests
from botocore.exceptions import ClientError

# ── Local modules (bundled in Lambda deployment package) ─────────────────────
from cis_checks     import CheckFinding, CheckStatus, run_all_checks
from pdf_generator  import generate_pdf_report

# ──────────────────────────────────────────────────────────────────────────────
# Logging — Lambda captures stdout/stderr to CloudWatch Logs automatically
# ──────────────────────────────────────────────────────────────────────────────
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("auro.orchestrator")


# ──────────────────────────────────────────────────────────────────────────────
# Configuration — read from environment at cold-start, not per-invocation
# ──────────────────────────────────────────────────────────────────────────────
SLACK_WEBHOOK_URL: Optional[str] = os.environ.get("SLACK_WEBHOOK_URL")
S3_REPORTS_BUCKET: Optional[str] = os.environ.get("S3_REPORTS_BUCKET")
AWS_REGION:        str            = os.environ.get("AWS_REGION", "us-east-1")

# Validate critical config at cold-start; logs appear in CloudWatch
if not SLACK_WEBHOOK_URL:
    logger.warning(
        "SLACK_WEBHOOK_URL is not set. Slack notifications will be skipped."
    )
if not S3_REPORTS_BUCKET:
    logger.warning(
        "S3_REPORTS_BUCKET is not set. PDF reports will not be uploaded to S3."
    )


# ──────────────────────────────────────────────────────────────────────────────
# Helper: resolve AWS Account ID at runtime
# ──────────────────────────────────────────────────────────────────────────────

def _get_account_id() -> str:
    """
    Retrieve the AWS account ID of the execution environment using STS.
    Falls back to a placeholder if STS is unreachable (e.g., during local testing).
    """
    try:
        sts = boto3.client("sts", region_name=AWS_REGION)
        return sts.get_caller_identity()["Account"]
    except ClientError as exc:
        logger.warning("Could not retrieve Account ID from STS: %s", exc)
        return "000000000000"


# ──────────────────────────────────────────────────────────────────────────────
# Step 1: Upload PDF to S3
# ──────────────────────────────────────────────────────────────────────────────

def _upload_pdf_to_s3(local_path: str, account_id: str) -> Optional[str]:
    """
    Upload the generated PDF from /tmp to S3.

    S3 key pattern: reports/<YYYY>/<MM>/<DD>/<filename>
    This partitioning scheme makes reports easy to query with Athena / S3 Select.

    Args:
        local_path:  Absolute path to PDF on Lambda's local filesystem.
        account_id:  AWS account ID (used in S3 key prefix).

    Returns:
        str: Public-facing S3 URI (s3://bucket/key) on success, None on failure.
    """
    if not S3_REPORTS_BUCKET:
        logger.info("S3_REPORTS_BUCKET not configured — skipping upload.")
        return None

    s3  = boto3.client("s3", region_name=AWS_REGION)
    now = datetime.now(timezone.utc)

    filename = os.path.basename(local_path)
    s3_key   = (
        f"reports/{now.year:04d}/{now.month:02d}/{now.day:02d}/{filename}"
    )

    try:
        with open(local_path, "rb") as pdf_file:
            s3.put_object(
                Bucket=S3_REPORTS_BUCKET,
                Key=s3_key,
                Body=pdf_file,
                ContentType="application/pdf",
                # Server-side encryption with AWS-managed keys
                ServerSideEncryption="AES256",
                Metadata={
                    "account-id":    account_id,
                    "region":        AWS_REGION,
                    "generated-utc": now.isoformat(),
                    "engine":        "auro-v1.0.0",
                },
            )
        s3_uri = f"s3://{S3_REPORTS_BUCKET}/{s3_key}"
        logger.info("PDF uploaded to S3: %s", s3_uri)
        return s3_uri

    except ClientError as exc:
        logger.error("Failed to upload PDF to S3: %s", exc)
        return None


# ──────────────────────────────────────────────────────────────────────────────
# Step 2: Send Slack Notification
# ──────────────────────────────────────────────────────────────────────────────

def _build_slack_payload(
    findings:      List[CheckFinding],
    account_id:    str,
    s3_uri:        Optional[str],
    report_date:   str,
) -> Dict[str, Any]:
    """
    Build a rich Slack Block Kit payload for the compliance summary notification.
    Block Kit produces visually structured messages with sections, fields, and
    colour-coded sidebars — far more useful than plain text for on-call teams.

    Args:
        findings:    Evaluated CIS findings.
        account_id:  AWS account ID.
        s3_uri:      S3 URI of the uploaded PDF, if available.
        report_date: ISO date string for the report.

    Returns:
        Dict: Slack API-compatible payload.
    """
    total  = len(findings)
    passed = sum(1 for f in findings if f.status == CheckStatus.PASS)
    failed = sum(1 for f in findings if f.status == CheckStatus.FAIL)
    errors = sum(1 for f in findings if f.status == CheckStatus.ERROR)
    score  = int((passed / total) * 100) if total else 0

    # Colour sidebar: green ≥ 80%, amber ≥ 50%, red otherwise
    sidebar_colour = (
        "#39D353" if score >= 80
        else "#D29922" if score >= 50
        else "#DA3633"
    )

    score_emoji = "🟢" if score >= 80 else "🟡" if score >= 50 else "🔴"

    # Build per-finding status lines
    finding_lines: List[str] = []
    for f in findings:
        icon = {
            CheckStatus.PASS:    "✅",
            CheckStatus.FAIL:    "❌",
            CheckStatus.ERROR:   "⚠️",
            CheckStatus.WARNING: "🟡",
        }.get(f.status, "❓")
        finding_lines.append(
            f"{icon} *{f.check_id}* — {f.title}  `{f.severity}`"
        )

    findings_text = "\n".join(finding_lines) if finding_lines else "_No findings._"

    # Optional S3 report link
    report_link_text = (
        f"\n\n📄 *PDF Report:* `{s3_uri}`" if s3_uri
        else "\n\n📄 _PDF report not uploaded (S3 bucket not configured)._"
    )

    payload = {
        "attachments": [
            {
                "color": sidebar_colour,
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": "☁️ Auro — Compliance Report Ready",
                            "emoji": True,
                        },
                    },
                    {"type": "divider"},
                    {
                        "type": "section",
                        "fields": [
                            {
                                "type": "mrkdwn",
                                "text": f"*Account ID*\n`{account_id}`",
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Region*\n`{AWS_REGION}`",
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Report Date*\n`{report_date}`",
                            },
                            {
                                "type": "mrkdwn",
                                "text": (
                                    f"*Compliance Score*\n"
                                    f"{score_emoji} `{score}%` "
                                    f"({passed}/{total} checks passed)"
                                ),
                            },
                        ],
                    },
                    {"type": "divider"},
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": (
                                f"*CIS Benchmark Findings*\n"
                                f"```\n"
                                f"PASS: {passed}  FAIL: {failed}  ERRORS: {errors}\n"
                                f"```\n"
                                + findings_text
                                + report_link_text
                            ),
                        },
                    },
                    {"type": "divider"},
                    {
                        "type": "context",
                        "elements": [
                            {
                                "type": "mrkdwn",
                                "text": (
                                    "🤖 Powered by *Auro v1.0.0* | "
                                    "CIS AWS Foundations Benchmark v1.4 | "
                                    "Triggered by Amazon EventBridge"
                                ),
                            }
                        ],
                    },
                ],
            }
        ]
    }

    return payload


def _send_slack_notification(
    findings:    List[CheckFinding],
    account_id:  str,
    s3_uri:      Optional[str],
    report_date: str,
) -> bool:
    """
    Dispatch the compliance summary to the configured Slack Incoming Webhook.

    Uses requests with a 10-second timeout. Failures are logged but do NOT
    raise — a Slack outage must never abort the Lambda execution.

    Returns:
        bool: True if Slack returned HTTP 200, False otherwise.
    """
    if not SLACK_WEBHOOK_URL:
        logger.info("Slack notification skipped — webhook URL not configured.")
        return False

    payload = _build_slack_payload(findings, account_id, s3_uri, report_date)

    try:
        resp = requests.post(
            SLACK_WEBHOOK_URL,
            json=payload,
            timeout=10,
            headers={"Content-Type": "application/json"},
        )
        resp.raise_for_status()
        logger.info("Slack notification sent successfully (HTTP %d).", resp.status_code)
        return True

    except requests.exceptions.Timeout:
        logger.error("Slack notification timed out after 10 seconds.")
    except requests.exceptions.HTTPError as exc:
        logger.error(
            "Slack API returned error %d: %s", exc.response.status_code, exc.response.text
        )
    except requests.exceptions.RequestException as exc:
        logger.error("Slack notification failed: %s", exc)

    return False


# ──────────────────────────────────────────────────────────────────────────────
# Step 3: Build structured Lambda response
# ──────────────────────────────────────────────────────────────────────────────

def _build_response(
    findings:    List[CheckFinding],
    account_id:  str,
    s3_uri:      Optional[str],
    slack_sent:  bool,
) -> Dict[str, Any]:
    """Construct a structured JSON response for Lambda invocation logs."""
    total  = len(findings)
    passed = sum(1 for f in findings if f.status == CheckStatus.PASS)
    failed = sum(1 for f in findings if f.status == CheckStatus.FAIL)
    errors = sum(1 for f in findings if f.status == CheckStatus.ERROR)

    return {
        "statusCode": 200,
        "engine":     "auro-v1.0.0",
        "account_id": account_id,
        "region":     AWS_REGION,
        "timestamp":  datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_checks": total,
            "passed":       passed,
            "failed":       failed,
            "errors":       errors,
            "compliance_pct": int((passed / total) * 100) if total else 0,
        },
        "findings": [
            {
                "check_id":   f.check_id,
                "title":      f.title,
                "status":     f.status.value,
                "severity":   f.severity,
                "resources":  f.resources,
            }
            for f in findings
        ],
        "artifacts": {
            "pdf_s3_uri":        s3_uri,
            "slack_notified":    slack_sent,
        },
    }


# ──────────────────────────────────────────────────────────────────────────────
# Lambda Entry Point
# ──────────────────────────────────────────────────────────────────────────────

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    AWS Lambda handler — orchestrates the full compliance pipeline.

    Execution flow:
      1. Resolve account metadata (STS GetCallerIdentity).
      2. Execute CIS Benchmark check suite via cis_checks.run_all_checks().
      3. Generate a professional PDF report via pdf_generator.generate_pdf_report().
      4. Upload the PDF to S3 (date-partitioned key).
      5. Push a rich Slack Block Kit summary notification.
      6. Return a structured JSON response (persisted in CloudWatch Logs).

    Args:
        event:   EventBridge scheduled event payload (or manual test event).
        context: Lambda runtime context (used for remaining_time_in_millis logging).

    Returns:
        Dict: Structured execution summary.
    """
    logger.info("=" * 70)
    logger.info("Auro Compliance Engine — invocation started.")
    logger.info(
        "Lambda: function=%s | version=%s | request_id=%s",
        getattr(context, "function_name", "local"),
        getattr(context, "function_version", "N/A"),
        getattr(context, "aws_request_id",   "N/A"),
    )

    if event:
        logger.debug("Event payload: %s", json.dumps(event, default=str))

    # ── Step 0: Metadata ─────────────────────────────────────────────────────
    account_id  = _get_account_id()
    report_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    logger.info("Target account: %s | Region: %s", account_id, AWS_REGION)

    # ── Step 1: Execute CIS checks ───────────────────────────────────────────
    logger.info("Step 1/4 — Running CIS Benchmark checks...")
    findings = run_all_checks()
    logger.info(
        "Step 1 complete: %d findings collected.", len(findings)
    )

    # ── Step 2: Generate PDF ──────────────────────────────────────────────────
    logger.info("Step 2/4 — Generating PDF compliance report...")
    try:
        pdf_path = generate_pdf_report(
            findings=findings,
            account_id=account_id,
            region=AWS_REGION,
            output_dir="/tmp",
        )
        logger.info("Step 2 complete: PDF at %s", pdf_path)
    except Exception as exc:
        logger.error("PDF generation failed: %s", exc, exc_info=True)
        pdf_path = None

    # ── Step 3: Upload to S3 ──────────────────────────────────────────────────
    logger.info("Step 3/4 — Uploading PDF to S3...")
    s3_uri = _upload_pdf_to_s3(pdf_path, account_id) if pdf_path else None

    # ── Step 4: Slack notification ────────────────────────────────────────────
    logger.info("Step 4/4 — Sending Slack notification...")
    slack_sent = _send_slack_notification(findings, account_id, s3_uri, report_date)

    # ── Build and return response ─────────────────────────────────────────────
    response = _build_response(findings, account_id, s3_uri, slack_sent)

    logger.info(
        "Pipeline complete. Score: %d%% (%d/%d checks passed). "
        "PDF: %s | Slack: %s",
        response["summary"]["compliance_pct"],
        response["summary"]["passed"],
        response["summary"]["total_checks"],
        s3_uri or "NOT_UPLOADED",
        "SENT" if slack_sent else "SKIPPED",
    )
    logger.info("=" * 70)

    return response


# ──────────────────────────────────────────────────────────────────────────────
# Local development entry point
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    """
    Run locally for development and testing.

    Usage:
        AWS_PROFILE=my-dev-profile python lambda_function.py

    The script will execute all checks against the active AWS profile,
    generate a PDF in /tmp (or current dir on non-Lambda), and print results.
    """

    class _FakeContext:
        function_name    = "auro-local-dev"
        function_version = "$LATEST"
        aws_request_id  = "local-dev-run"

    test_event = {
        "source":      "aws.events",
        "detail-type": "Scheduled Event",
        "detail":      {},
    }

    result = lambda_handler(test_event, _FakeContext())
    print("\n" + "=" * 70)
    print("LOCAL RUN RESULT:")
    print(json.dumps(result, indent=2, default=str))
