from datetime import datetime, timezone
from botocore.exceptions import ClientError


def check_securityhub_enabled(session) -> dict:
    """
    SEC-001: Checks whether AWS Security Hub is enabled in the configured AWS region.

    Evidence source:
    securityhub.describe_hub()
    """
    securityhub = session.client("securityhub")

    control_id = "SEC-001"
    control_name = "Security Hub Enabled"

    try:
        hub_response = securityhub.describe_hub()

        status = "PASS" if hub_response.get("HubArn") else "FAIL"

        return {
            "control_id": control_id,
            "control_name": control_name,
            "control_domain": "Security Posture Management",
            "aws_service": "Security Hub",
            "status": status,
            "risk_rating": "Medium",
            "evidence_source": "securityhub.describe_hub",
            "evidence": {
                "hub_arn": hub_response.get("HubArn"),
                "subscribed_at": hub_response.get("SubscribedAt"),
                "auto_enable_controls": hub_response.get("AutoEnableControls"),
                "control_finding_generator": hub_response.get(
                    "ControlFindingGenerator"
                )
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "remediation": (
                "Enable AWS Security Hub to centralize security findings, "
                "compliance checks, and cloud security posture visibility."
            )
        }

    except ClientError as error:
        error_code = error.response.get("Error", {}).get("Code")

        if error_code in [
            "InvalidAccessException",
            "ResourceNotFoundException"
        ]:
            return {
                "control_id": control_id,
                "control_name": control_name,
                "control_domain": "Security Posture Management",
                "aws_service": "Security Hub",
                "status": "FAIL",
                "risk_rating": "Medium",
                "evidence_source": "securityhub.describe_hub",
                "evidence": {
                    "security_hub_enabled": False,
                    "error_code": error_code
                },
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "remediation": (
                    "Enable AWS Security Hub in the AWS account and configure "
                    "required standards such as CIS AWS Foundations or AWS "
                    "Foundational Security Best Practices."
                )
            }

        return {
            "control_id": control_id,
            "control_name": control_name,
            "control_domain": "Security Posture Management",
            "aws_service": "Security Hub",
            "status": "ERROR",
            "risk_rating": "Medium",
            "evidence_source": "securityhub.describe_hub",
            "evidence": {},
            "error": str(error),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "remediation": (
                "Verify Security Hub permissions and retry the control check."
            )
        }