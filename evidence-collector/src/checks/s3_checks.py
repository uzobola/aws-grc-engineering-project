from datetime import datetime, timezone
from botocore.exceptions import ClientError


def check_s3_public_access_block_enabled(session) -> dict:
    """
    S3-001: Checks whether S3 buckets have public access block enabled.

    Evidence source:
    s3.list_buckets()
    s3.get_public_access_block()
    """
    s3 = session.client("s3")

    control_id = "S3-001"
    control_name = "S3 Public Access Block Enabled"

    try:
        buckets_response = s3.list_buckets()
        buckets = buckets_response.get("Buckets", [])

        evaluated_buckets = []
        non_compliant_buckets = []

        required_settings = {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True
        }

        for bucket in buckets:
            bucket_name = bucket.get("Name")

            try:
                pab_response = s3.get_public_access_block(Bucket=bucket_name)
                config = pab_response.get("PublicAccessBlockConfiguration", {})

                is_compliant = all(
                    config.get(setting) == expected_value
                    for setting, expected_value in required_settings.items()
                )

                bucket_result = {
                    "bucket_name": bucket_name,
                    "public_access_block_configured": True,
                    "settings": config,
                    "compliant": is_compliant
                }

                if not is_compliant:
                    non_compliant_buckets.append(bucket_name)

            except ClientError as error:
                error_code = error.response.get("Error", {}).get("Code")

                bucket_result = {
                    "bucket_name": bucket_name,
                    "public_access_block_configured": False,
                    "settings": {},
                    "compliant": False,
                    "error": error_code
                }

                non_compliant_buckets.append(bucket_name)

            evaluated_buckets.append(bucket_result)

        status = "PASS" if len(non_compliant_buckets) == 0 else "FAIL"

        return {
            "control_id": control_id,
            "control_name": control_name,
            "control_domain": "Data Protection",
            "aws_service": "S3",
            "status": status,
            "risk_rating": "Critical",
            "evidence_source": "s3.list_buckets + s3.get_public_access_block",
            "evidence": {
                "total_buckets_evaluated": len(evaluated_buckets),
                "non_compliant_bucket_count": len(non_compliant_buckets),
                "non_compliant_buckets": non_compliant_buckets,
                "evaluated_buckets": evaluated_buckets
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "remediation": "Enable S3 Block Public Access for all buckets using all four public access block settings."
        }

    except ClientError as error:
        return {
            "control_id": control_id,
            "control_name": control_name,
            "control_domain": "Data Protection",
            "aws_service": "S3",
            "status": "ERROR",
            "risk_rating": "Critical",
            "evidence_source": "s3.list_buckets + s3.get_public_access_block",
            "evidence": {},
            "error": str(error),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "remediation": "Verify S3 permissions and retry the control check."
        }


def check_s3_default_encryption_enabled(session) -> dict:
    """
    S3-002: Checks whether S3 buckets have default encryption enabled.

    Evidence source:
    s3.list_buckets()
    s3.get_bucket_encryption()
    """
    s3 = session.client("s3")

    control_id = "S3-002"
    control_name = "S3 Default Encryption Enabled"

    try:
        buckets_response = s3.list_buckets()
        buckets = buckets_response.get("Buckets", [])

        evaluated_buckets = []
        non_compliant_buckets = []

        for bucket in buckets:
            bucket_name = bucket.get("Name")

            try:
                encryption_response = s3.get_bucket_encryption(Bucket=bucket_name)
                rules = encryption_response.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])

                encryption_algorithms = []

                for rule in rules:
                    default_encryption = rule.get("ApplyServerSideEncryptionByDefault", {})
                    algorithm = default_encryption.get("SSEAlgorithm")
                    kms_key_id = default_encryption.get("KMSMasterKeyID")

                    encryption_algorithms.append({
                        "algorithm": algorithm,
                        "kms_key_id": kms_key_id
                    })

                is_compliant = len(encryption_algorithms) > 0

                bucket_result = {
                    "bucket_name": bucket_name,
                    "default_encryption_configured": True,
                    "encryption_algorithms": encryption_algorithms,
                    "compliant": is_compliant
                }

                if not is_compliant:
                    non_compliant_buckets.append(bucket_name)

            except ClientError as error:
                error_code = error.response.get("Error", {}).get("Code")

                bucket_result = {
                    "bucket_name": bucket_name,
                    "default_encryption_configured": False,
                    "encryption_algorithms": [],
                    "compliant": False,
                    "error": error_code
                }

                non_compliant_buckets.append(bucket_name)

            evaluated_buckets.append(bucket_result)

        status = "PASS" if len(non_compliant_buckets) == 0 else "FAIL"

        return {
            "control_id": control_id,
            "control_name": control_name,
            "control_domain": "Data Protection",
            "aws_service": "S3",
            "status": status,
            "risk_rating": "High",
            "evidence_source": "s3.list_buckets + s3.get_bucket_encryption",
            "evidence": {
                "total_buckets_evaluated": len(evaluated_buckets),
                "non_compliant_bucket_count": len(non_compliant_buckets),
                "non_compliant_buckets": non_compliant_buckets,
                "evaluated_buckets": evaluated_buckets
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "remediation": "Enable default server-side encryption for all S3 buckets using SSE-S3 or SSE-KMS based on the control baseline."
        }

    except ClientError as error:
        return {
            "control_id": control_id,
            "control_name": control_name,
            "control_domain": "Data Protection",
            "aws_service": "S3",
            "status": "ERROR",
            "risk_rating": "High",
            "evidence_source": "s3.list_buckets + s3.get_bucket_encryption",
            "evidence": {},
            "error": str(error),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "remediation": "Verify S3 permissions and retry the control check."
        }