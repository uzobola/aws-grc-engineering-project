from datetime import datetime, timezone
from botocore.exceptions import ClientError


def check_guardduty_enabled(session) -> dict:
    """
    DET-001: Checks whether GuardDuty is enabled in the configured AWS region.

    Evidence source:
    guardduty.list_detectors()
    guardduty.get_detector()
    """
    guardduty = session.client("guardduty")

    control_id = "DET-001"
    control_name = "GuardDuty Enabled"

    try:
        detectors_response = guardduty.list_detectors()
        detector_ids = detectors_response.get("DetectorIds", [])

        evaluated_detectors = []

        for detector_id in detector_ids:
            detector_response = guardduty.get_detector(DetectorId=detector_id)

            evaluated_detectors.append({
                "detector_id": detector_id,
                "status": detector_response.get("Status"),
                "service_role": detector_response.get("ServiceRole"),
                "finding_publishing_frequency": detector_response.get(
                    "FindingPublishingFrequency"
                ),
                "created_at": detector_response.get("CreatedAt"),
                "updated_at": detector_response.get("UpdatedAt")
            })

        enabled_detectors = [
            detector for detector in evaluated_detectors
            if detector.get("status") == "ENABLED"
        ]

        status = "PASS" if len(enabled_detectors) > 0 else "FAIL"

        return {
            "control_id": control_id,
            "control_name": control_name,
            "control_domain": "Threat Detection",
            "aws_service": "GuardDuty",
            "status": status,
            "risk_rating": "High",
            "evidence_source": "guardduty.list_detectors + guardduty.get_detector",
            "evidence": {
                "total_detectors_evaluated": len(evaluated_detectors),
                "enabled_detector_count": len(enabled_detectors),
                "evaluated_detectors": evaluated_detectors
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "remediation": (
                "Enable Amazon GuardDuty in the AWS account and configure it "
                "for required regions to support threat detection and monitoring."
            )
        }

    except ClientError as error:
        return {
            "control_id": control_id,
            "control_name": control_name,
            "control_domain": "Threat Detection",
            "aws_service": "GuardDuty",
            "status": "ERROR",
            "risk_rating": "High",
            "evidence_source": "guardduty.list_detectors + guardduty.get_detector",
            "evidence": {},
            "error": str(error),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "remediation": (
                "Verify GuardDuty permissions and retry the control check."
            )
        }