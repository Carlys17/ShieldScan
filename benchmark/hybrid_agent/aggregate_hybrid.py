#!/usr/bin/env python3
"""
Merge ShieldScan regex findings with Claude Code AI findings into
a single EVMbench submission.

Used as a fallback when Claude Code output needs augmentation or
when Claude Code is unavailable.

Usage:
    python aggregate_hybrid.py --shieldscan hints.json --output audit.md
    python aggregate_hybrid.py --shieldscan hints.json --claude-output claude_audit.md --output audit.md
"""

import argparse
import json
import re
from pathlib import Path
from typing import List, Dict, Any


def extract_json_from_md(content: str) -> Dict[str, Any]:
    """Extract the JSON block from a markdown file."""
    match = re.search(r'```json\s*\n(.*?)\n```', content, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass
    # Try raw JSON extraction
    start = content.find('{')
    if start >= 0:
        depth = 0
        for i in range(start, len(content)):
            if content[i] == '{':
                depth += 1
            elif content[i] == '}':
                depth -= 1
            if depth == 0:
                try:
                    return json.loads(content[start:i + 1])
                except json.JSONDecodeError:
                    break
    return {"vulnerabilities": []}


def shieldscan_to_vuln(finding: dict) -> dict:
    """Convert a ShieldScan JSON finding to EVMbench vulnerability format."""
    return {
        "title": f"[ShieldScan] {finding.get('name', 'Unknown')}",
        "severity": finding.get("severity", "medium").lower(),
        "summary": finding.get("description", ""),
        "description": [{
            "file": finding.get("source_file", "unknown.sol"),
            "line_start": finding.get("line", 0),
            "line_end": finding.get("end_line") or finding.get("line", 0),
            "desc": f"{finding.get('name', '')} ({finding.get('swc', '')}): "
                    f"{finding.get('code', '')}",
        }],
        "impact": finding.get("description", ""),
        "proof_of_concept": f"Detected at line {finding.get('line', '?')}: "
                            f"{finding.get('code', '')}",
        "remediation": finding.get("recommendation", ""),
    }


def deduplicate(vulns: List[dict]) -> List[dict]:
    """Remove duplicates by title + location."""
    seen = set()
    result = []
    for v in vulns:
        descs = v.get("description", [])
        loc = f"{descs[0].get('file', '')}:{descs[0].get('line_start', 0)}" if descs else ""
        key = f"{v['title'].lower().strip()}|{loc}"
        if key not in seen:
            seen.add(key)
            result.append(v)
    return result


def merge(shieldscan_path: str, claude_output_path: str = None, output_path: str = "audit.md"):
    """Merge ShieldScan and optional Claude Code findings."""
    ss_data = json.loads(Path(shieldscan_path).read_text(encoding="utf-8"))
    ss_findings = ss_data.get("shieldscan_findings", [])
    ss_vulns = [shieldscan_to_vuln(f) for f in ss_findings]

    claude_vulns = []
    if claude_output_path and Path(claude_output_path).exists():
        claude_content = Path(claude_output_path).read_text(encoding="utf-8")
        claude_data = extract_json_from_md(claude_content)
        claude_vulns = claude_data.get("vulnerabilities", [])

    # Claude findings first (higher quality), then ShieldScan
    all_vulns = claude_vulns + ss_vulns
    deduped = deduplicate(all_vulns)

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    deduped.sort(key=lambda v: severity_order.get(v.get("severity", "low"), 4))

    report = {"vulnerabilities": deduped}
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        f"# Hybrid ShieldScan + Claude Code Audit Report\n\n"
        f"```json\n{json.dumps(report, indent=2)}\n```\n",
        encoding="utf-8",
    )

    source = f"{len(claude_vulns)} Claude + {len(ss_vulns)} ShieldScan"
    print(f"[Hybrid Merge] {len(deduped)} vulnerabilities ({source})")


def main():
    parser = argparse.ArgumentParser(description="Merge ShieldScan + Claude Code findings")
    parser.add_argument("--shieldscan", required=True, help="Path to shieldscan_hints.json")
    parser.add_argument("--claude-output", default=None, help="Path to Claude Code audit.md")
    parser.add_argument("--output", required=True, help="Output path for merged audit.md")
    args = parser.parse_args()
    merge(args.shieldscan, args.claude_output, args.output)


if __name__ == "__main__":
    main()
