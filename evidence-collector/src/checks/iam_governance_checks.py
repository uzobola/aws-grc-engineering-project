import csv
import io
import time
from pathlib import Path
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

def _extract_aws_principals_from_trust_policy(trust_policy: dict) -> list[str]:
    """
    Extracts AWS principals from an IAM role trust policy.

    Trust policies may include:
    - Principal as a string
    - Principal as a dictionary
    - AWS principal as a string
    - AWS principal as a list
    """
    principals = []
    statements = trust_policy.get("Statement", [])

    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:
        principal = statement.get("Principal", {})

        if isinstance(principal, str):
            principals.append(principal)
            continue

        aws_principal = principal.get("AWS") if isinstance(principal, dict) else None

        if isinstance(aws_principal, str):
            principals.append(aws_principal)
        elif isinstance(aws_principal, list):
            principals.extend(aws_principal)

    return principals


def _principal_is_external_account(principal: str, current_account_id: str) -> bool:
    """
    Determines whether an AWS principal belongs to an external AWS account.

    Examples:
    - arn:aws:iam::123456789012:root
    - arn:aws:iam::123456789012:role/SomeRole
    - 123456789012
    """
    if not principal:
        return False

    if principal == "*":
        return True

    if principal.isdigit() and len(principal) == 12:
        return principal != current_account_id

    account_marker = "arn:aws:iam::"

    if principal.startswith(account_marker):
        account_id = principal.split(":")[4]
        return account_id != current_account_id

    return False


def check_cross_account_role_trust(session) -> dict:
    """
    IAM-007: Identifies IAM roles with trust relationships to external AWS accounts.

    Evidence source:
    iam.list_roles()
    Role AssumeRolePolicyDocument

    A role is flagged when its trust policy allows an AWS principal from
    outside the current AWS account.
    """
    iam = session.client("iam")
    sts = session.client("sts")

    control_id = "IAM-007"
    control_name = "Cross-Account Role Trust Review"

    try:
        current_account_id = sts.get_caller_identity().get("Account")

        evaluated_roles = []
        cross_account_roles = []

        role_paginator = iam.get_paginator("list_roles")

        for role_page in role_paginator.paginate():
            for role in role_page.get("Roles", []):
                role_name = role.get("RoleName")
                role_arn = role.get("Arn")
                trust_policy = role.get("AssumeRolePolicyDocument", {})

                aws_principals = _extract_aws_principals_from_trust_policy(
                    trust_policy
                )

                external_principals = [
                    principal for principal in aws_principals
                    if _principal_is_external_account(
                        principal,
                        current_account_id
                    )
                ]

                is_cross_account = len(external_principals) > 0

                role_result = {
                    "role_name": role_name,
                    "role_arn": role_arn,
                    "trusted_aws_principals": aws_principals,
                    "external_principals": external_principals,
                    "is_cross_account": is_cross_account
                }

                evaluated_roles.append(role_result)

                if is_cross_account:
                    cross_account_roles.append(role_result)

        status = "PASS" if len(cross_account_roles) == 0 else "FAIL"

        return {
            "control_id": control_id,
            "control_name": control_name,
            "control_domain": "Identity and Access Management",
            "aws_service": "IAM",
            "status": status,
            "risk_rating": "High",
            "evidence_source": "iam.list_roles + role trust policy analysis",
            "evidence": {
                "current_account_id": current_account_id,
                "total_roles_evaluated": len(evaluated_roles),
                "cross_account_role_count": len(cross_account_roles),
                "cross_account_roles": cross_account_roles,
                "evaluated_roles": evaluated_roles
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "remediation": (
                "Review cross-account role trust relationships with the "
                "appropriate control owner. Remove unapproved external "
                "principals, require ExternalId where appropriate, and document "
                "approved third-party or multi-account access exceptions."
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
            "evidence_source": "iam.list_roles + role trust policy analysis",
            "evidence": {},
            "error": str(error),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "remediation": (
                "Verify IAM and STS permissions for listing roles and retrieving "
                "caller identity."
            )
        }  


def check_iam_access_analyzer_findings(session) -> dict:
    """
    IAM-008: Identifies active IAM Access Analyzer findings.

    Evidence source:
    accessanalyzer.list_analyzers()
    accessanalyzer.list_findings()

    A finding represents external or public access identified by IAM Access Analyzer.
    This control fails when active findings are present.
    """
    access_analyzer = session.client("accessanalyzer")

    control_id = "IAM-008"
    control_name = "IAM Access Analyzer Findings"

    try:
        analyzers_response = access_analyzer.list_analyzers()
        analyzers = analyzers_response.get("analyzers", [])

        if len(analyzers) == 0:
            return {
                "control_id": control_id,
                "control_name": control_name,
                "control_domain": "Identity and Access Management",
                "aws_service": "IAM Access Analyzer",
                "status": "FAIL",
                "risk_rating": "High",
                "evidence_source": "accessanalyzer.list_analyzers",
                "evidence": {
                    "access_analyzer_configured": False,
                    "total_analyzers_evaluated": 0,
                    "active_finding_count": 0
                    },
                 "timestamp": datetime.now(timezone.utc).isoformat(),
                   "remediation": (
                       "Create an IAM Access Analyzer analyzer to continuously "
                    "identify external and public access findings."
                    )
                }

        evaluated_analyzers = []
        active_findings = []

        for analyzer in analyzers:
            analyzer_name = analyzer.get("name")
            analyzer_arn = analyzer.get("arn")
            analyzer_type = analyzer.get("type")
            analyzer_status = analyzer.get("status")

            analyzer_result = {
                "analyzer_name": analyzer_name,
                "analyzer_arn": analyzer_arn,
                "analyzer_type": analyzer_type,
                "analyzer_status": analyzer_status,
                "active_findings": []
            }

            findings_paginator = access_analyzer.get_paginator("list_findings")

            for findings_page in findings_paginator.paginate(
                analyzerArn=analyzer_arn,
                filter={
                    "status": {
                        "eq": ["ACTIVE"]
                    }
                }
            ):
                for finding in findings_page.get("findings", []):
                    finding_result = {
                        "finding_id": finding.get("id"),
                        "resource": finding.get("resource"),
                        "resource_type": finding.get("resourceType"),
                        "principal": finding.get("principal"),
                        "condition": finding.get("condition"),
                        "action": finding.get("action"),
                        "status": finding.get("status"),
                        "created_at": (
                            finding.get("createdAt").isoformat()
                            if finding.get("createdAt") else None
                        ),
                        "updated_at": (
                            finding.get("updatedAt").isoformat()
                            if finding.get("updatedAt") else None
                        )
                    }

                    analyzer_result["active_findings"].append(finding_result)
                    active_findings.append(finding_result)

            evaluated_analyzers.append(analyzer_result)

        status = "PASS" if len(active_findings) == 0 else "FAIL"

        return {
            "control_id": control_id,
            "control_name": control_name,
            "control_domain": "Identity and Access Management",
            "aws_service": "IAM Access Analyzer",
            "status": status,
            "risk_rating": "High",
            "evidence_source": (
                "accessanalyzer.list_analyzers + accessanalyzer.list_findings"
            ),
            "evidence": {
                "total_analyzers_evaluated": len(evaluated_analyzers),
                "active_finding_count": len(active_findings),
                "active_findings": active_findings,
                "evaluated_analyzers": evaluated_analyzers
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "remediation": (
                "Review active IAM Access Analyzer findings. Remove unintended "
                "public or external access, document approved external access, "
                "and archive findings only after validation."
            )
        }

    except ClientError as error:
        error_code = error.response.get("Error", {}).get("Code")
        error_message = error.response.get("Error", {}).get("Message")

        if error_code in [
            "AccessDeniedException",
            "ResourceNotFoundException",
            "ValidationException"
        ]:
            return {
                "control_id": control_id,
                "control_name": control_name,
                "control_domain": "Identity and Access Management",
                "aws_service": "IAM Access Analyzer",
                "status": "FAIL",
                "risk_rating": "High",
                "evidence_source": (
                    "accessanalyzer.list_analyzers + accessanalyzer.list_findings"
                ),
                "evidence": {
                    "access_analyzer_available": False,
                    "error_code": error_code,
                    "error_message": error_message
                },
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "remediation": (
                    "Enable IAM Access Analyzer and ensure the collector role "
                    "has permissions to list analyzers and findings."
                )
            }

        return {
            "control_id": control_id,
            "control_name": control_name,
            "control_domain": "Identity and Access Management",
            "aws_service": "IAM Access Analyzer",
            "status": "ERROR",
            "risk_rating": "High",
            "evidence_source": (
                "accessanalyzer.list_analyzers + accessanalyzer.list_findings"
            ),
            "evidence": {},
            "error_code": error_code,
            "error_message": error_message,
            "error": str(error),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "remediation": (
                "Verify IAM Access Analyzer permissions and retry the control check."
            )
        }

def check_quarterly_access_review_evidence(session) -> dict:
    """
    IAM-009: Generates structured IAM access review evidence.

    Evidence source:
    iam.list_users()
    iam.list_mfa_devices()
    iam.list_access_keys()
    iam.list_attached_user_policies()
    iam.list_user_policies()

    This control does not fail simply because users exist. It passes when
    access review evidence can be generated successfully.

    The output supports quarterly access certification by providing reviewers
    with IAM user, MFA, access key, and policy assignment context.
    """
    iam = session.client("iam")

    control_id = "IAM-009"
    control_name = "Quarterly Access Review Evidence"

    try:
        access_review_records = []

        user_paginator = iam.get_paginator("list_users")

        for user_page in user_paginator.paginate():
            for user in user_page.get("Users", []):
                username = user.get("UserName")
                user_arn = user.get("Arn")
                created_date = user.get("CreateDate")

                mfa_response = iam.list_mfa_devices(UserName=username)
                mfa_devices = mfa_response.get("MFADevices", [])

                access_keys = []
                key_paginator = iam.get_paginator("list_access_keys")

                for key_page in key_paginator.paginate(UserName=username):
                    for access_key in key_page.get("AccessKeyMetadata", []):
                        access_key_id = access_key.get("AccessKeyId")

                        last_used_response = iam.get_access_key_last_used(
                            AccessKeyId=access_key_id
                        )

                        last_used = last_used_response.get(
                            "AccessKeyLastUsed",
                            {}
                        )

                        access_keys.append({
                            "access_key_id_masked": (
                                f"{access_key_id[:4]}...{access_key_id[-4:]}"
                                if access_key_id else None
                            ),
                            "status": access_key.get("Status"),
                            "created_date": (
                                access_key.get("CreateDate").isoformat()
                                if access_key.get("CreateDate") else None
                            ),
                            "last_used_date": (
                                last_used.get("LastUsedDate").isoformat()
                                if last_used.get("LastUsedDate") else None
                            ),
                            "last_used_service": last_used.get("ServiceName"),
                            "last_used_region": last_used.get("Region")
                        })

                attached_policies = []
                attached_policy_paginator = iam.get_paginator(
                    "list_attached_user_policies"
                )

                for policy_page in attached_policy_paginator.paginate(
                    UserName=username
                ):
                    for policy in policy_page.get("AttachedPolicies", []):
                        attached_policies.append({
                            "policy_name": policy.get("PolicyName"),
                            "policy_arn": policy.get("PolicyArn")
                        })

                inline_policies = []
                inline_policy_paginator = iam.get_paginator(
                    "list_user_policies"
                )

                for inline_page in inline_policy_paginator.paginate(
                    UserName=username
                ):
                    for policy_name in inline_page.get("PolicyNames", []):
                        inline_policies.append(policy_name)

                review_record = {
                    "principal_name": username,
                    "principal_type": "IAM User",
                    "principal_arn": user_arn,
                    "created_date": (
                        created_date.isoformat()
                        if created_date else None
                    ),
                    "mfa_enabled": len(mfa_devices) > 0,
                    "mfa_device_count": len(mfa_devices),
                    "access_key_count": len(access_keys),
                    "access_keys": access_keys,
                    "attached_policy_count": len(attached_policies),
                    "attached_policies": attached_policies,
                    "inline_policy_count": len(inline_policies),
                    "inline_policies": inline_policies,
                    "review_decision": "Pending",
                    "reviewer": "TBD",
                    "review_notes": ""
                }

                access_review_records.append(review_record)

        return {
            "control_id": control_id,
            "control_name": control_name,
            "control_domain": "Identity and Access Management",
            "aws_service": "IAM",
            "status": "PASS",
            "risk_rating": "Medium",
            "evidence_source": (
                "iam.list_users + iam.list_mfa_devices + "
                "iam.list_access_keys + iam.get_access_key_last_used + "
                "iam.list_attached_user_policies + iam.list_user_policies"
            ),
            "evidence": {
                "review_frequency": "Quarterly",
                "total_principals_reviewed": len(access_review_records),
                "access_review_records": access_review_records
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "remediation": (
                "Provide generated access review evidence to control owners. "
                "Reviewers should certify, revoke, or document exceptions for "
                "each principal based on business need and least privilege."
            )
        }

    except ClientError as error:
        return {
            "control_id": control_id,
            "control_name": control_name,
            "control_domain": "Identity and Access Management",
            "aws_service": "IAM",
            "status": "ERROR",
            "risk_rating": "Medium",
            "evidence_source": (
                "iam.list_users + iam.list_mfa_devices + "
                "iam.list_access_keys + iam.get_access_key_last_used + "
                "iam.list_attached_user_policies + iam.list_user_policies"
            ),
            "evidence": {},
            "error": str(error),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "remediation": (
                "Verify IAM permissions required to generate access review evidence."
            )
        }

def check_leaver_offboarding_validation(
    session,
    leaver_file_path: str = "../iam-governance/sample-data/leavers.csv"
) -> dict:
    """
    IAM-010: Validates that terminated users do not retain active IAM access.

    Evidence source:
    iam.list_users()
    iam.get_login_profile()
    leaver source CSV

    The leaver file represents a source of truth for terminated users.
    This control compares expected disabled users against active IAM users.
    """
    iam = session.client("iam")

    control_id = "IAM-010"
    control_name = "Leaver Offboarding Validation"

    try:
        leaver_path = Path(leaver_file_path)

        if not leaver_path.exists():
            return {
                "control_id": control_id,
                "control_name": control_name,
                "control_domain": "Identity and Access Management",
                "aws_service": "IAM",
                "status": "ERROR",
                "risk_rating": "Critical",
                "evidence_source": "leaver source file + iam.list_users",
                "evidence": {
                    "leaver_file_path": str(leaver_path),
                    "file_found": False
                },
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "remediation": (
                    "Provide a valid leaver source file for offboarding validation."
                )
            }

        with leaver_path.open("r", encoding="utf-8") as file:
            leaver_records = list(csv.DictReader(file))

        expected_disabled_users = {
            record.get("aws_iam_user")
            for record in leaver_records
            if record.get("expected_access_status", "").lower() == "disabled"
            and record.get("aws_iam_user")
        }

        active_iam_users = {}
        user_paginator = iam.get_paginator("list_users")

        for user_page in user_paginator.paginate():
            for user in user_page.get("Users", []):
                username = user.get("UserName")

                console_access_enabled = False

                try:
                    iam.get_login_profile(UserName=username)
                    console_access_enabled = True
                except ClientError as profile_error:
                    error_code = profile_error.response.get("Error", {}).get("Code")

                    if error_code != "NoSuchEntity":
                        raise

                active_iam_users[username] = {
                    "user_name": username,
                    "user_arn": user.get("Arn"),
                    "created_date": (
                        user.get("CreateDate").isoformat()
                        if user.get("CreateDate") else None
                    ),
                    "console_access_enabled": console_access_enabled
                }

        offboarding_gaps = []

        for record in leaver_records:
            aws_iam_user = record.get("aws_iam_user")
            expected_status = record.get("expected_access_status")

            if not aws_iam_user:
                continue

            iam_user_exists = aws_iam_user in active_iam_users

            validation_result = "PASS"

            if (
                expected_status
                and expected_status.lower() == "disabled"
                and iam_user_exists
            ):
                validation_result = "FAIL"

                offboarding_gaps.append({
                    "employee_id": record.get("employee_id"),
                    "employee_name": record.get("employee_name"),
                    "termination_date": record.get("termination_date"),
                    "aws_iam_user": aws_iam_user,
                    "expected_access_status": expected_status,
                    "actual_access_status": "Active",
                    "console_access_enabled": active_iam_users[
                        aws_iam_user
                    ].get("console_access_enabled")
                })

        status = "PASS" if len(offboarding_gaps) == 0 else "FAIL"

        return {
            "control_id": control_id,
            "control_name": control_name,
            "control_domain": "Identity and Access Management",
            "aws_service": "IAM",
            "status": status,
            "risk_rating": "Critical",
            "evidence_source": "leaver source file + iam.list_users + iam.get_login_profile",
            "evidence": {
                "leaver_file_path": str(leaver_path),
                "total_leaver_records": len(leaver_records),
                "expected_disabled_user_count": len(expected_disabled_users),
                "active_iam_user_count": len(active_iam_users),
                "offboarding_gap_count": len(offboarding_gaps),
                "offboarding_gaps": offboarding_gaps
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "remediation": (
                "Disable or delete IAM users associated with terminated employees. "
                "Validate offboarding with HR, IAM, and control owners. Document "
                "approved exceptions for break-glass or retained access scenarios."
            )
        }

    except ClientError as error:
        return {
            "control_id": control_id,
            "control_name": control_name,
            "control_domain": "Identity and Access Management",
            "aws_service": "IAM",
            "status": "ERROR",
            "risk_rating": "Critical",
            "evidence_source": "leaver source file + iam.list_users + iam.get_login_profile",
            "evidence": {},
            "error": str(error),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "remediation": (
                "Verify IAM permissions for listing users and checking login profiles."
            )
        }