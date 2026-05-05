import csv
import json
from pathlib import Path


def write_json(results: list[dict], output_path: Path) -> None:
    """
    Writes evidence results to a JSON file.
    """
    with output_path.open("w", encoding="utf-8") as file:
        json.dump(results, file, indent=2)


def write_csv(results: list[dict], output_path: Path) -> None:
    """
    Writes evidence results to a CSV file.
    """
    fieldnames = [
        "control_id",
        "control_name",
        "control_domain",
        "aws_service",
        "status",
        "risk_rating",
        "evidence_source",
        "timestamp",
        "remediation"
    ]

    with output_path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()

        for result in results:
            writer.writerow({
                "control_id": result.get("control_id"),
                "control_name": result.get("control_name"),
                "control_domain": result.get("control_domain"),
                "aws_service": result.get("aws_service"),
                "status": result.get("status"),
                "risk_rating": result.get("risk_rating"),
                "evidence_source": result.get("evidence_source"),
                "timestamp": result.get("timestamp"),
                "remediation": result.get("remediation")
            })
