from pathlib import Path
import yaml

from checks.iam_checks import (
    check_root_mfa_enabled,
    check_no_active_root_access_keys
)
from evidence.evidence_writer import write_json, write_csv
from utils.aws_session import create_aws_session


def load_config() -> dict:
    """
    Loads collector configuration from config.yaml.
    """
    config_path = Path("config.yaml")

    with config_path.open("r", encoding="utf-8") as file:
        return yaml.safe_load(file)


def main() -> None:
    config = load_config()

    profile_name = config["aws"]["profile"]
    region_name = config["aws"]["region"]

    output_directory = Path(config["output"]["directory"])
    output_directory.mkdir(exist_ok=True)

    json_output_path = output_directory / config["output"]["json_file"]
    csv_output_path = output_directory / config["output"]["csv_file"]

    session = create_aws_session(
        profile_name=profile_name,
        region_name=region_name
    )

    results = [
        check_root_mfa_enabled(session),
        check_no_active_root_access_keys(session)
    ]

    write_json(results, json_output_path)
    write_csv(results, csv_output_path)

    print("Evidence collection complete.")
    print(f"JSON output: {json_output_path}")
    print(f"CSV output:  {csv_output_path}")

    for result in results:
        print(
            f"{result['control_id']} | "
            f"{result['control_name']} | "
            f"{result['status']} | "
            f"{result['risk_rating']}"
        )


if __name__ == "__main__":
    main()
