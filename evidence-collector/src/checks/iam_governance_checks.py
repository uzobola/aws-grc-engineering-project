import csv
import io
import time
from datetime import datetime, timezone, timedelta
from botocore.exceptions import ClientError


def _parse_credential_report_datetime(value: str):
    """
    Parses IAM credential report date values.

    AWS credential report fields may contain:
    - ISO-like timestamp values
    - "N/A"
    - "no_information"

    Returns:
    datetime object or None.
    """
    if not value or value in ["N/A", "no_information", "not_supported"]:
        return None

    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S%z")
    except ValueError:
        return None


def _most_recent_activity(dates: list):
    """
    Returns the most recent non-null datetime from a list.
    """
    valid_dates = [date for date in dates if date is not None]

    if not valid_dates:
        return None

    return max(valid_dates)


def check_stale_iam_users(session, stale_days: int = 90) -> dict:
    """
    IAM-004: Identifies IAM users with no recent credential activity.

    Evidence source:
    iam.generate_credential_report()
    iam.get_credential_report()

    A user is considered stale if the most recent observed activity across
    password and access keys is older than the stale_days threshold, or if
    there is no activity information available.
    """
    iam = session.client("iam")

    control_id = "IAM-004"
    control_name = "Stale IAM Users"

    try:
        for attempt in range(10):
            generation_response = iam.generate_credential_report()
            state = generation_response.get("State")

            if state == "COMPLETE":
                break

            time.sleep(2)

        credential_report_response = iam.get_credential_report()

        report_content = credential_report_response["Content"].decode("utf-8")
        report_reader = csv.DictReader(io.StringIO(report_content))

        now = datetime.now(timezone.utc)
        stale_cutoff = now - timedelta(days=stale_days)

        evaluated_users = []
        stale_users = []

        for row in report_reader:
            username = row.get("user")

            # Skip AWS account root row. Root is covered by IAM-001 and IAM-002.
            if username == "<root_account>":
                continue

            password_last_used = _parse_credential_report_datetime(
                row.get("password_last_used")
            )
            access_key_1_last_used = _parse_credential_report_datetime(
                row.get("access_key_1_last_used_date")
            )
            access_key_2_last_used = _parse_credential_report_datetime(
                row.get("access_key_2_last_used_date")
            )

            recent_activity = _most_recent_activity([
                password_last_used,
                access_key_1_last_used,
                access_key_2_last_used
            ])

            is_stale = recent_activity is None or recent_activity < stale_cutoff

            user_result = {
                "user_name": username,
                "arn": row.get("arn"),
                "user_creation_time": row.get("user_creation_time"),
                "password_enabled": row.get("password_enabled"),
                "password_last_used": row.get("password_last_used"),
                "access_key_1_active": row.get("access_key_1_active"),
                "access_key_1_last_used_date": row.get("access_key_1_last_used_date"),
                "access_key_2_active": row.get("access_key_2_active"),
                "access_key_2_last_used_date": row.get("access_key_2_last_used_date"),
                "most_recent_activity": (
                    recent_activity.isoformat()
                    if recent_activity else None
                ),
                "stale_threshold_days": stale_days,
                "is_stale": is_stale
            }

            evaluated_users.append(user_result)

            if is_stale:
                stale_users.append(username)

        status = "PASS" if len(stale_users) == 0 else "FAIL"

        return {
            "control_id": control_id,
            "control_name": control_name,
            "control_domain": "Identity and Access Management",
            "aws_service": "IAM",
            "status": status,
            "risk_rating": "High",
            "evidence_source": (
                "iam.generate_credential_report + iam.get_credential_report"
            ),
            "evidence": {
                "stale_threshold_days": stale_days,
                "total_users_evaluated": len(evaluated_users),
                "stale_user_count": len(stale_users),
                "stale_users": stale_users,
                "evaluated_users": evaluated_users
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "remediation": (
                "Review stale IAM users with the appropriate control owner. "
                "Disable, remove, or document an approved exception for users "
                "with no recent activity."
            )
        }

    except ClientError as error:
        return {
            "control_id": control_id,
            "control_name": control_name,
            "control_domain": "Identity and Access Management",
            "aws_service": "IAM",
            "status": "ERROR",
            "risk_rating": "High",
            "evidence_source": (
                "iam.generate_credential_report + iam.get_credential_report"
            ),
            "evidence": {},
            "error": str(error),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "remediation": (
                "Verify IAM permissions for credential report generation and retrieval."
            )
        }



def check_unused_access_keys(session, unused_days: int = 90) -> dict:
    """
    IAM-005: Identifies active IAM access keys that have not been used recently.

    Evidence source:
    iam.list_users()
    iam.list_access_keys()
    iam.get_access_key_last_used()

    An access key is considered unused if:
    - It is active, and
    - It has never been used, or
    - Its last used date is older than the unused_days threshold.
    """
    iam = session.client("iam")

    control_id = "IAM-005"
    control_name = "Unused Access Keys"

    try:
        now = datetime.now(timezone.utc)
        unused_cutoff = now - timedelta(days=unused_days)

        evaluated_keys = []
        unused_access_keys = []

        user_paginator = iam.get_paginator("list_users")

        for user_page in user_paginator.paginate():
            for user in user_page.get("Users", []):
                username = user.get("UserName")

                key_paginator = iam.get_paginator("list_access_keys")

                for key_page in key_paginator.paginate(UserName=username):
                    for access_key in key_page.get("AccessKeyMetadata", []):
                        access_key_id = access_key.get("AccessKeyId")
                        key_status = access_key.get("Status")
                        created_date = access_key.get("CreateDate")

                        last_used_response = iam.get_access_key_last_used(
                            AccessKeyId=access_key_id
                        )

                        access_key_last_used = last_used_response.get(
                            "AccessKeyLastUsed",
                            {}
                        )

                        last_used_date = access_key_last_used.get("LastUsedDate")
                        last_used_service = access_key_last_used.get("ServiceName")
                        last_used_region = access_key_last_used.get("Region")

                        is_active = key_status == "Active"

                        if last_used_date is None:
                            is_unused = is_active
                        else:
                            is_unused = is_active and last_used_date < unused_cutoff

                        key_result = {
                            "user_name": username,
                            "access_key_id_masked": (
                                f"{access_key_id[:4]}...{access_key_id[-4:]}"
                                if access_key_id else None
                            ),
                            "status": key_status,
                            "created_date": (
                                created_date.isoformat()
                                if created_date else None
                            ),
                            "last_used_date": (
                                last_used_date.isoformat()
                                if last_used_date else None
                            ),
                            "last_used_service": last_used_service,
                            "last_used_region": last_used_region,
                            "unused_threshold_days": unused_days,
                            "is_unused": is_unused
                        }

                        evaluated_keys.append(key_result)

                        if is_unused:
                            unused_access_keys.append({
                                "user_name": username,
                                "access_key_id_masked": key_result[
                                    "access_key_id_masked"
                                ],
                                "last_used_date": key_result["last_used_date"],
                                "status": key_status
                            })

        status = "PASS" if len(unused_access_keys) == 0 else "FAIL"

        return {
            "control_id": control_id,
            "control_name": control_name,
            "control_domain": "Identity and Access Management",
            "aws_service": "IAM",
            "status": status,
            "risk_rating": "High",
            "evidence_source": (
                "iam.list_users + iam.list_access_keys + "
                "iam.get_access_key_last_used"
            ),
            "evidence": {
                "unused_threshold_days": unused_days,
                "total_access_keys_evaluated": len(evaluated_keys),
                "unused_access_key_count": len(unused_access_keys),
                "unused_access_keys": unused_access_keys,
                "evaluated_keys": evaluated_keys
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "remediation": (
                "Review unused active access keys with the appropriate owner. "
                "Deactivate or delete keys that are no longer required. Rotate "
                "keys that are still needed and document approved exceptions."
            )
        }

    except ClientError as error:
        return {
            "control_id": control_id,
            "control_name": control_name,
            "control_domain": "Identity and Access Management",
            "aws_service": "IAM",
            "status": "ERROR",
            "risk_rating": "High",
            "evidence_source": (
                "iam.list_users + iam.list_access_keys + "
                "iam.get_access_key_last_used"
            ),
            "evidence": {},
            "error": str(error),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "remediation": (
                "Verify IAM permissions for listing users, listing access keys, "
                "and retrieving access key last-used metadata."
            )
        }