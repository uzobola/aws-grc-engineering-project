import json
from pathlib import Path
from datetime import datetime, timezone


RISK_WEIGHTS = {
    "Critical": 5,
    "High": 4,
    "Medium": 3,
    "Low": 2,
    "Informational": 1
}


def load_evidence(evidence_file: Path) -> list[dict]:
    """
    Loads evidence results from the evidence collector JSON output.
    """
    if not evidence_file.exists():
        raise FileNotFoundError(f"Evidence file not found: {evidence_file}")

    with evidence_file.open("r", encoding="utf-8") as file:
        return json.load(file)


def calculate_compliance_score(results: list[dict]) -> float:
    """
    Calculates the percentage of controls that passed.
    """
    total_controls = len(results)

    if total_controls == 0:
        return 0.0

    passed_controls = len([
        result for result in results
        if result.get("status") == "PASS"
    ])

    return round((passed_controls / total_controls) * 100, 2)


def summarize_results(results: list[dict]) -> dict:
    """
    Creates a risk-based summary of control results.
    """
    passed = []
    failed = []
    errors = []

    for result in results:
        status = result.get("status")

        if status == "PASS":
            passed.append(result)
        elif status == "FAIL":
            failed.append(result)
        else:
            errors.append(result)

    failed_by_risk = {}

    for result in failed:
        risk_rating = result.get("risk_rating", "Unknown")
        failed_by_risk.setdefault(risk_rating, []).append({
            "control_id": result.get("control_id"),
            "control_name": result.get("control_name"),
            "aws_service": result.get("aws_service"),
            "remediation": result.get("remediation")
        })

    remediation_priorities = sorted(
        failed,
        key=lambda item: RISK_WEIGHTS.get(item.get("risk_rating"), 0),
        reverse=True
    )

    top_remediation_priorities = [
        {
            "control_id": result.get("control_id"),
            "control_name": result.get("control_name"),
            "aws_service": result.get("aws_service"),
            "risk_rating": result.get("risk_rating"),
            "remediation": result.get("remediation")
        }
        for result in remediation_priorities
    ]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_controls_evaluated": len(results),
        "passed_controls": len(passed),
        "failed_controls": len(failed),
        "error_controls": len(errors),
        "compliance_score_percent": calculate_compliance_score(results),
        "failed_controls_by_risk": failed_by_risk,
        "top_remediation_priorities": top_remediation_priorities
    }


def write_report(summary: dict, output_file: Path) -> None:
    """
    Writes the risk summary to a JSON report.
    """
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with output_file.open("w", encoding="utf-8") as file:
        json.dump(summary, file, indent=2)


def print_summary(summary: dict) -> None:
    """
    Prints a readable summary to the terminal.
    """
    print("AWS GRC Risk Scoring Summary")
    print("=" * 32)
    print(f"Generated At: {summary['generated_at']}")
    print(f"Total Controls Evaluated: {summary['total_controls_evaluated']}")
    print(f"Passed Controls: {summary['passed_controls']}")
    print(f"Failed Controls: {summary['failed_controls']}")
    print(f"Error Controls: {summary['error_controls']}")
    print(f"Compliance Score: {summary['compliance_score_percent']}%")
    print()

    print("Top Remediation Priorities:")
    print("-" * 28)

    if not summary["top_remediation_priorities"]:
        print("No failed controls. No remediation required.")
        return

    for index, item in enumerate(summary["top_remediation_priorities"], start=1):
        print(
            f"{index}. {item['control_id']} | "
            f"{item['control_name']} | "
            f"{item['risk_rating']} | "
            f"{item['aws_service']}"
        )
        print(f"   Remediation: {item['remediation']}")


def main() -> None:
    evidence_file = Path("../evidence-collector/output/evidence-results.json")
    output_file = Path("output/risk-summary.json")

    results = load_evidence(evidence_file)
    summary = summarize_results(results)

    write_report(summary, output_file)
    print_summary(summary)

    print()
    print(f"Risk summary written to: {output_file}")


if __name__ == "__main__":
    main()