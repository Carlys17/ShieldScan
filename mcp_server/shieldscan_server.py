#!/usr/bin/env python3
"""ShieldScan MCP Server — Expose ShieldScan as Claude Code tools via MCP."""

import sys
import json
import time
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from mcp.server.fastmcp import FastMCP
from scanner import ShieldScanner, PATTERNS, Severity, format_json, format_text, format_markdown

mcp = FastMCP(
    "ShieldScan",
    instructions="Smart contract vulnerability scanner for Solidity. "
    "Provides tools to scan .sol files for 14+ vulnerability patterns.",
)


# ─── Tools ─────────────────────────────────────────────────────────────

@mcp.tool()
def scan_file(file_path: str, format: str = "json") -> str:
    """Scan a Solidity (.sol) file for vulnerabilities.

    Args:
        file_path: Absolute or relative path to a .sol file.
        format: Output format — "json" (default), "text", or "markdown".

    Returns:
        Scan results in the requested format.
    """
    path = Path(file_path)
    if not path.exists():
        return json.dumps({"error": f"File not found: {file_path}"})

    scanner = ShieldScanner()
    start = time.time()
    source = path.read_text(encoding="utf-8")
    scanner.scan(source)
    elapsed = time.time() - start

    formatters = {"json": format_json, "text": format_text, "markdown": format_markdown}
    formatter = formatters.get(format, format_json)
    return formatter(scanner, str(path), elapsed)


@mcp.tool()
def scan_code(source_code: str) -> str:
    """Scan raw Solidity source code for vulnerabilities.

    Args:
        source_code: Complete Solidity source code as a string.

    Returns:
        JSON string with findings array and summary.
    """
    scanner = ShieldScanner()
    start = time.time()
    scanner.scan(source_code)
    elapsed = time.time() - start

    return json.dumps({
        "tool": "ShieldScan",
        "scan_time": f"{elapsed:.2f}s",
        "summary": scanner.get_summary(),
        "findings": [f.to_dict() for f in scanner.findings],
    }, indent=2)


@mcp.tool()
def scan_directory(directory_path: str, exclude_dirs: Optional[str] = None) -> str:
    """Recursively scan all .sol files in a directory.

    Args:
        directory_path: Path to directory containing .sol files.
        exclude_dirs: Comma-separated directory names to skip
                      (default: "lib,node_modules,test,tests,forge-std,.git").

    Returns:
        JSON string with per-file findings and aggregate summary.
    """
    dir_path = Path(directory_path)
    if not dir_path.is_dir():
        return json.dumps({"error": f"Directory not found: {directory_path}"})

    excluded = set(
        (exclude_dirs or "lib,node_modules,test,tests,forge-std,.git").split(",")
    )
    sol_files = []
    for sol_file in sorted(dir_path.rglob("*.sol")):
        parts = sol_file.relative_to(dir_path).parts
        if any(p.strip() in excluded for p in parts):
            continue
        sol_files.append(sol_file)

    all_results = []
    total_summary = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}

    start = time.time()
    for sol_file in sol_files:
        scanner = ShieldScanner()
        try:
            source = sol_file.read_text(encoding="utf-8")
            scanner.scan(source)
        except Exception as e:
            all_results.append({"file": str(sol_file), "error": str(e)})
            continue

        summary = scanner.get_summary()
        for key in total_summary:
            total_summary[key] += summary[key]

        all_results.append({
            "file": str(sol_file.relative_to(dir_path)),
            "summary": summary,
            "findings": [f.to_dict() for f in scanner.findings],
        })
    elapsed = time.time() - start

    return json.dumps({
        "tool": "ShieldScan",
        "directory": directory_path,
        "files_scanned": len(sol_files),
        "scan_time": f"{elapsed:.2f}s",
        "aggregate_summary": total_summary,
        "results": all_results,
    }, indent=2)


@mcp.tool()
def get_patterns() -> str:
    """List all vulnerability detection patterns with descriptions.

    Returns:
        JSON array of pattern objects with name, severity, swc, description,
        recommendation, and references.
    """
    patterns_info = []
    for p in PATTERNS:
        patterns_info.append({
            "name": p["name"],
            "severity": p["severity"].value,
            "swc": p["swc"],
            "regex": p["pattern"],
            "description": p["description"],
            "recommendation": p["recommendation"],
            "references": p.get("references", []),
            "has_context_check": "context_check" in p,
        })
    return json.dumps(patterns_info, indent=2)


# ─── Resources ─────────────────────────────────────────────────────────

@mcp.resource("shieldscan://patterns")
def patterns_resource() -> str:
    """All ShieldScan vulnerability pattern definitions."""
    return get_patterns()


@mcp.resource("shieldscan://swc/{swc_id}")
def swc_resource(swc_id: str) -> str:
    """SWC registry information for a specific ID (e.g., SWC-107)."""
    normalized = swc_id if swc_id.startswith("SWC-") else f"SWC-{swc_id}"
    matched = [p for p in PATTERNS if p["swc"] == normalized]
    if not matched:
        return json.dumps({
            "error": f"No pattern found for {normalized}",
            "registry_url": f"https://swcregistry.io/docs/{normalized}",
        })
    results = []
    for p in matched:
        results.append({
            "name": p["name"],
            "severity": p["severity"].value,
            "swc": p["swc"],
            "description": p["description"],
            "recommendation": p["recommendation"],
            "references": p.get("references", []),
            "registry_url": f"https://swcregistry.io/docs/{normalized}",
        })
    return json.dumps(results, indent=2)


# ─── Entry Point ───────────────────────────────────────────────────────

if __name__ == "__main__":
    mcp.run(transport="stdio")
