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

def _policy_has_wildcard_admin_access(policy_document: dict) -> bool:
    """
    Detects broad wildcard administrative permissions in an IAM policy document.

    This is a conservative check. It flags policies where:
    - Effect is Allow
    - Action is "*" or contains "*"
    - Resource is "*" or contains "*"
    """
    statements = policy_document.get("Statement", [])

    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue

        actions = statement.get("Action", [])
        resources = statement.get("Resource", [])

        if isinstance(actions, str):
            actions = [actions]

        if isinstance(resources, str):
            resources = [resources]

        has_wildcard_action = "*" in actions
        has_wildcard_resource = "*" in resources

        if has_wildcard_action and has_wildcard_resource:
            return True

    return False


def check_privileged_iam_users(session) -> dict:
    """
    IAM-006: Identifies IAM users with privileged access.

    Evidence source:
    iam.list_users()
    iam.list_attached_user_policies()
    iam.get_policy()
    iam.get_policy_version()
    iam.list_user_policies()
    iam.get_user_policy()

    A user is considered privileged if:
    - AdministratorAccess is attached
    - PowerUserAccess is attached
    - IAMFullAccess is attached
    - An attached or inline policy allows Action "*" on Resource "*"
    """
    iam = session.client("iam")

    control_id = "IAM-006"
    control_name = "Privileged IAM Users"

    privileged_policy_names = {
        "AdministratorAccess",
        "PowerUserAccess",
        "IAMFullAccess"
    }

    try:
        evaluated_users = []
        privileged_users = []

        user_paginator = iam.get_paginator("list_users")

        for user_page in user_paginator.paginate():
            for user in user_page.get("Users", []):
                username = user.get("UserName")
                user_arn = user.get("Arn")

                user_findings = []

                attached_policy_paginator = iam.get_paginator(
                    "list_attached_user_policies"
                )

                for policy_page in attached_policy_paginator.paginate(
                    UserName=username
                ):
                    for attached_policy in policy_page.get("AttachedPolicies", []):
                        policy_name = attached_policy.get("PolicyName")
                        policy_arn = attached_policy.get("PolicyArn")

                        if policy_name in privileged_policy_names:
                            user_findings.append({
                                "finding_type": "managed_policy",
                                "policy_name": policy_name,
                                "policy_arn": policy_arn,
                                "reason": "Known privileged AWS managed policy attached directly to user"
                            })

                        policy_metadata = iam.get_policy(PolicyArn=policy_arn)
                        default_version_id = policy_metadata["Policy"][
                            "DefaultVersionId"
                        ]

                        policy_version = iam.get_policy_version(
                            PolicyArn=policy_arn,
                            VersionId=default_version_id
                        )

                        policy_document = policy_version["PolicyVersion"][
                            "Document"
                        ]

                        if _policy_has_wildcard_admin_access(policy_document):
                            user_findings.append({
                                "finding_type": "managed_policy_wildcard",
                                "policy_name": policy_name,
                                "policy_arn": policy_arn,
                                "reason": "Managed policy allows wildcard Action and wildcard Resource"
                            })

                inline_policy_paginator = iam.get_paginator("list_user_policies")

                for inline_page in inline_policy_paginator.paginate(
                    UserName=username
                ):
                    for inline_policy_name in inline_page.get("PolicyNames", []):
                        inline_policy_response = iam.get_user_policy(
                            UserName=username,
                            PolicyName=inline_policy_name
                        )

                        inline_policy_document = inline_policy_response[
                            "PolicyDocument"
                        ]

                        if _policy_has_wildcard_admin_access(
                            inline_policy_document
                        ):
                            user_findings.append({
                                "finding_type": "inline_policy_wildcard",
                                "policy_name": inline_policy_name,
                                "policy_arn": None,
                                "reason": "Inline policy allows wildcard Action and wildcard Resource"
                            })

                is_privileged = len(user_findings) > 0

                user_result = {
                    "user_name": username,
                    "user_arn": user_arn,
                    "is_privileged": is_privileged,
                    "findings": user_findings
                }

                evaluated_users.append(user_result)

                if is_privileged:
                    privileged_users.append({
                        "user_name": username,
                        "user_arn": user_arn,
                        "finding_count": len(user_findings),
                        "findings": user_findings
                    })

        status = "PASS" if len(privileged_users) == 0 else "FAIL"

        return {
            "control_id": control_id,
            "control_name": control_name,
            "control_domain": "Identity and Access Management",
            "aws_service": "IAM",
            "status": status,
            "risk_rating": "High",
            "evidence_source": (
                "iam.list_users + iam.list_attached_user_policies + "
                "iam.get_policy_version + iam.list_user_policies + "
                "iam.get_user_policy"
            ),
            "evidence": {
                "total_users_evaluated": len(evaluated_users),
                "privileged_user_count": len(privileged_users),
                "privileged_users": privileged_users,
                "evaluated_users": evaluated_users
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "remediation": (
                "Review privileged IAM users with the appropriate control owner. "
                "Remove direct administrative policies where possible, migrate "
                "human access to federated roles, and apply least-privilege "
                "permissions based on job function."
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
                "iam.list_users + iam.list_attached_user_policies + "
                "iam.get_policy_version + iam.list_user_policies + "
                "iam.get_user_policy"
            ),
            "evidence": {},
            "error": str(error),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "remediation": (
                "Verify IAM permissions for listing users and reading managed "
                "and inline policy documents."
            )
        }