#!/usr/bin/env python3
"""
Aggregate per-file ShieldScan JSON outputs into a single EVMbench submission.

Usage:
    python aggregate.py --scan-dir /tmp/scans --audit-dir /home/agent/audit --output submission/audit.md
"""

import argparse
import json
from pathlib import Path


def aggregate_scans(scan_dir: str, audit_dir: str) -> dict:
    """Read all scan_*.json files and merge into a single vulnerability list.

    Deduplicates by (name, file, line_number) tuple.
    Maps findings to EVMbench ReportModel schema.
    """
    all_vulns = []
    seen = set()

    scan_path = Path(scan_dir)
    audit_path = Path(audit_dir)

    for json_file in sorted(scan_path.glob("scan_*.json")):
        try:
            data = json.loads(json_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, FileNotFoundError):
            continue

        target_file = data.get("target", "unknown.sol")
        try:
            rel_path = str(Path(target_file).relative_to(audit_path))
        except ValueError:
            rel_path = Path(target_file).name

        for finding in data.get("findings", []):
            key = (finding["name"], rel_path, finding["line"])
            if key in seen:
                continue
            seen.add(key)

            vuln = {
                "title": finding["name"],
                "severity": finding["severity"].lower(),
                "summary": finding["description"],
                "description": [{
                    "file": rel_path,
                    "line_start": finding["line"],
                    "line_end": finding.get("end_line") or finding["line"],
                    "desc": f"{finding['name']} ({finding.get('swc', '')}): {finding.get('code', '')}"
                }],
                "impact": finding["description"],
                "proof_of_concept": f"Detected at line {finding['line']}: {finding.get('code', '')}",
                "remediation": finding.get("recommendation", "")
            }
            all_vulns.append(vuln)

    return {"vulnerabilities": all_vulns}


def main():
    parser = argparse.ArgumentParser(
        description="Aggregate ShieldScan scan results into EVMbench submission"
    )
    parser.add_argument("--scan-dir", required=True,
                        help="Directory containing scan_*.json files")
    parser.add_argument("--audit-dir", required=True,
                        help="Audit source directory (for relative paths)")
    parser.add_argument("--output", required=True,
                        help="Output path for audit.md submission")
    args = parser.parse_args()

    report = aggregate_scans(args.scan_dir, args.audit_dir)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    md_content = (
        f"# ShieldScan Audit Report\n\n"
        f"```json\n{json.dumps(report, indent=2)}\n```\n"
    )
    output_path.write_text(md_content, encoding="utf-8")

    print(f"Aggregated {len(report['vulnerabilities'])} findings into {args.output}")


if __name__ == "__main__":
    main()
