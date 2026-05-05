from datetime import datetime, timezone
from botocore.exceptions import ClientError


def check_root_mfa_enabled(session) -> dict:
    """
    IAM-001: Checks whether MFA is enabled for the AWS account root user.

    Evidence source:
    iam.get_account_summary()
    """
    iam = session.client("iam")

    control_id = "IAM-001"
    control_name = "Root MFA Enabled"

    try:
        response = iam.get_account_summary()
        summary = response.get("SummaryMap", {})
        root_mfa_enabled = summary.get("AccountMFAEnabled", 0)

        status = "PASS" if root_mfa_enabled == 1 else "FAIL"

        return {
            "control_id": control_id,
            "control_name": control_name,
            "control_domain": "Identity and Access Management",
            "aws_service": "IAM",
            "status": status,
            "risk_rating": "Critical",
            "evidence_source": "iam.get_account_summary",
            "evidence": {
                "AccountMFAEnabled": root_mfa_enabled
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "remediation": "Enable MFA for the AWS account root user."
        }

    except ClientError as error:
        return {
            "control_id": control_id,
            "control_name": control_name,
            "control_domain": "Identity and Access Management",
            "aws_service": "IAM",
            "status": "ERROR",
            "risk_rating": "Critical",
            "evidence_source": "iam.get_account_summary",
            "evidence": {},
            "error": str(error),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "remediation": "Verify IAM permissions and retry the control check."
        }


def check_no_active_root_access_keys(session) -> dict:
    """
    IAM-002: Checks whether the AWS account root user has active access keys.

    Evidence source:
    iam.get_account_summary()
    """
    iam = session.client("iam")

    control_id = "IAM-002"
    control_name = "No Active Root Access Keys"

    try:
        response = iam.get_account_summary()
        summary = response.get("SummaryMap", {})
        root_access_keys = summary.get("AccountAccessKeysPresent", 0)

        status = "PASS" if root_access_keys == 0 else "FAIL"

        return {
            "control_id": control_id,
            "control_name": control_name,
            "control_domain": "Identity and Access Management",
            "aws_service": "IAM",
            "status": status,
            "risk_rating": "Critical",
            "evidence_source": "iam.get_account_summary",
            "evidence": {
                "AccountAccessKeysPresent": root_access_keys
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "remediation": "Delete active access keys for the AWS account root user."
        }

    except ClientError as error:
        return {
            "control_id": control_id,
            "control_name": control_name,
            "control_domain": "Identity and Access Management",
            "aws_service": "IAM",
            "status": "ERROR",
            "risk_rating": "Critical",
            "evidence_source": "iam.get_account_summary",
            "evidence": {},
            "error": str(error),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "remediation": "Verify IAM permissions and retry the control check."
        }


def check_iam_users_have_mfa(session) -> dict:
    """
    IAM-003: Checks whether IAM users have MFA configured.

    Evidence source:
    iam.list_users()
    iam.list_mfa_devices()
    """
    iam = session.client("iam")

    control_id = "IAM-003"
    control_name = "IAM Users Have MFA"

    try:
        users = []
        paginator = iam.get_paginator("list_users")

        for page in paginator.paginate():
            users.extend(page.get("Users", []))

        evaluated_users = []
        users_without_mfa = []

        for user in users:
            username = user.get("UserName")

            mfa_response = iam.list_mfa_devices(UserName=username)
            mfa_devices = mfa_response.get("MFADevices", [])

            has_mfa = len(mfa_devices) > 0

            user_result = {
                "user_name": username,
                "user_arn": user.get("Arn"),
                "has_mfa": has_mfa,
                "mfa_device_count": len(mfa_devices)
            }

            evaluated_users.append(user_result)

            if not has_mfa:
                users_without_mfa.append(username)

        status = "PASS" if len(users_without_mfa) == 0 else "FAIL"

        return {
            "control_id": control_id,
            "control_name": control_name,
            "control_domain": "Identity and Access Management",
            "aws_service": "IAM",
            "status": status,
            "risk_rating": "High",
            "evidence_source": "iam.list_users + iam.list_mfa_devices",
            "evidence": {
                "total_users_evaluated": len(evaluated_users),
                "users_without_mfa_count": len(users_without_mfa),
                "users_without_mfa": users_without_mfa,
                "evaluated_users": evaluated_users
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "remediation": "Enable MFA for all IAM users, especially users with console access or privileged permissions."
        }

    except ClientError as error:
        return {
            "control_id": control_id,
            "control_name": control_name,
            "control_domain": "Identity and Access Management",
            "aws_service": "IAM",
            "status": "ERROR",
            "risk_rating": "High",
            "evidence_source": "iam.list_users + iam.list_mfa_devices",
            "evidence": {},
            "error": str(error),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "remediation": "Verify IAM permissions and retry the control check."
        }
