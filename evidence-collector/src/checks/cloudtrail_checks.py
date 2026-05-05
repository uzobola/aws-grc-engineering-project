from datetime import datetime, timezone
from botocore.exceptions import ClientError


def check_cloudtrail_enabled(session) -> dict:
    """
    LOG-001: Checks whether CloudTrail is enabled and actively logging.

    Evidence source:
    cloudtrail.describe_trails()
    cloudtrail.get_trail_status()
    """
    cloudtrail = session.client("cloudtrail")

    control_id = "LOG-001"
    control_name = "CloudTrail Enabled"

    try:
        trails_response = cloudtrail.describe_trails(includeShadowTrails=True)
        trails = trails_response.get("trailList", [])

        evaluated_trails = []
        active_logging_trails = []

        for trail in trails:
            trail_name = trail.get("Name")
            trail_arn = trail.get("TrailARN")
            is_multi_region = trail.get("IsMultiRegionTrail", False)
            log_file_validation_enabled = trail.get(
                "LogFileValidationEnabled",
                False
            )

            try:
                trail_status = cloudtrail.get_trail_status(Name=trail_arn)
                is_logging = trail_status.get("IsLogging", False)

                trail_result = {
                    "trail_name": trail_name,
                    "trail_arn": trail_arn,
                    "is_logging": is_logging,
                    "is_multi_region": is_multi_region,
                    "log_file_validation_enabled": log_file_validation_enabled,
                    "latest_delivery_time": str(
                        trail_status.get("LatestDeliveryTime")
                    ),
                    "latest_delivery_error": trail_status.get(
                        "LatestDeliveryError"
                    )
                }

                if is_logging:
                    active_logging_trails.append(trail_name)

            except ClientError as trail_error:
                trail_result = {
                    "trail_name": trail_name,
                    "trail_arn": trail_arn,
                    "is_logging": False,
                    "is_multi_region": is_multi_region,
                    "log_file_validation_enabled": log_file_validation_enabled,
                    "error": str(trail_error)
                }

            evaluated_trails.append(trail_result)

        status = "PASS" if len(active_logging_trails) > 0 else "FAIL"

        return {
            "control_id": control_id,
            "control_name": control_name,
            "control_domain": "Logging and Monitoring",
            "aws_service": "CloudTrail",
            "status": status,
            "risk_rating": "Critical",
            "evidence_source": (
                "cloudtrail.describe_trails + cloudtrail.get_trail_status"
            ),
            "evidence": {
                "total_trails_evaluated": len(evaluated_trails),
                "active_logging_trail_count": len(active_logging_trails),
                "active_logging_trails": active_logging_trails,
                "evaluated_trails": evaluated_trails
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "remediation": (
                "Create or enable at least one CloudTrail trail and ensure "
                "it is actively logging. For stronger governance, configure "
                "a multi-region trail with log file validation enabled."
            )
        }

    except ClientError as error:
        return {
            "control_id": control_id,
            "control_name": control_name,
            "control_domain": "Logging and Monitoring",
            "aws_service": "CloudTrail",
            "status": "ERROR",
            "risk_rating": "Critical",
            "evidence_source": (
                "cloudtrail.describe_trails + cloudtrail.get_trail_status"
            ),
            "evidence": {},
            "error": str(error),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "remediation": (
                "Verify CloudTrail permissions and retry the control check."
            )
        }