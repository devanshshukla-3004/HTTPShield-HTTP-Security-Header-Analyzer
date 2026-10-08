import csv
import json
from pathlib import Path


def write_json(report: dict, path: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2), encoding="utf-8")


def write_csv(report: dict, path: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fields = ["id", "title", "status", "severity", "score", "category", "evidence", "remediation"]
    with target.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for check in report.get("checks", []):
            writer.writerow({field: check.get(field, "") for field in fields})
