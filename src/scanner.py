#!/usr/bin/env python3
"""
ShieldScan — Smart Contract Vulnerability Scanner
==================================================
A static analysis tool to detect common security vulnerabilities in Solidity smart contracts.

Usage:
    python scanner.py <file.sol> [-f json|markdown|text|evmbench] [-o output_file]

Author: Carlys17
License: MIT
"""

import re
import sys
import json
import argparse
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional
from pathlib import Path


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    """Represents a single vulnerability finding."""
    name: str
    severity: Severity
    description: str
    line_number: int
    end_line: Optional[int]
    code_snippet: str
    recommendation: str
    swc_id: str
    references: List[str] = field(default_factory=list)

    def to_dict(self):
        return {
            "name": self.name,
            "severity": self.severity.value,
            "description": self.description,
            "line": self.line_number,
            "end_line": self.end_line,
            "code": self.code_snippet,
            "recommendation": self.recommendation,
            "swc": self.swc_id,
            "references": self.references
        }


# ─── Vulnerability Patterns ───────────────────────────────────────────

PATTERNS = [
    {
        "name": "Reentrancy Vulnerability",
        "severity": Severity.CRITICAL,
        "swc": "SWC-107",
        "pattern": r'\.call\{.*?value.*?\}\s*\(',
        "context_check": lambda lines, idx: _check_state_after_call(lines, idx),
        "description": "External call detected before state changes. An attacker can re-enter the function to drain funds.",
        "recommendation": "Apply Checks-Effects-Interactions pattern. Update state BEFORE external calls. Use OpenZeppelin ReentrancyGuard.",
        "references": ["https://swcregistry.io/docs/SWC-107"]
    },
    {
        "name": "tx.origin Authentication",
        "severity": Severity.HIGH,
        "swc": "SWC-115",
        "pattern": r'(require|if)\s*\(.*tx\.origin',
        "description": "Using tx.origin for authorization is vulnerable to phishing attacks via intermediary contracts.",
        "recommendation": "Replace tx.origin with msg.sender for authentication.",
        "references": ["https://swcregistry.io/docs/SWC-115"]
    },
    {
        "name": "Unchecked Call Return Value",
        "severity": Severity.HIGH,
        "swc": "SWC-104",
        "pattern": r'\.call\s*\(',
        "context_check": lambda lines, idx: _check_unchecked_return(lines, idx),
        "description": "Return value of low-level call is not checked. Silent failures can lead to unexpected behavior.",
        "recommendation": "Always check the return value of .call() and handle failures explicitly.",
        "references": ["https://swcregistry.io/docs/SWC-104"]
    },
    {
        "name": "Delegatecall to Untrusted Contract",
        "severity": Severity.CRITICAL,
        "swc": "SWC-112",
        "pattern": r'\.delegatecall\s*\(',
        "description": "Delegatecall executes code in the caller's context. If the target is untrusted, it can modify storage arbitrarily.",
        "recommendation": "Only delegatecall to trusted, audited contracts. Validate target address.",
        "references": ["https://swcregistry.io/docs/SWC-112"]
    },
    {
        "name": "Unprotected Selfdestruct",
        "severity": Severity.CRITICAL,
        "swc": "SWC-106",
        "pattern": r'selfdestruct\s*\(',
        "context_check": lambda lines, idx: _check_missing_access_control(lines, idx),
        "description": "selfdestruct can permanently destroy the contract and send remaining ETH to an arbitrary address.",
        "recommendation": "Add strict access control (onlyOwner) to any function containing selfdestruct.",
        "references": ["https://swcregistry.io/docs/SWC-106"]
    },
    {
        "name": "Timestamp Dependence",
        "severity": Severity.MEDIUM,
        "swc": "SWC-116",
        "pattern": r'block\.timestamp',
        "description": "block.timestamp can be manipulated by miners within a ~15 second window.",
        "recommendation": "Avoid using block.timestamp for critical logic. Use block.number or commit-reveal schemes.",
        "references": ["https://swcregistry.io/docs/SWC-116"]
    },
    {
        "name": "Block Number Dependence",
        "severity": Severity.LOW,
        "swc": "SWC-120",
        "pattern": r'block\.number',
        "description": "Using block.number for randomness or time-sensitive logic is predictable.",
        "recommendation": "Use Chainlink VRF for randomness. Avoid block.number for critical decisions.",
        "references": ["https://swcregistry.io/docs/SWC-120"]
    },
    {
        "name": "Floating Pragma",
        "severity": Severity.LOW,
        "swc": "SWC-103",
        "pattern": r'pragma\s+solidity\s*\^',
        "description": "Floating pragma allows compilation with different compiler versions, potentially introducing bugs.",
        "recommendation": "Lock the pragma to a specific version (e.g., pragma solidity 0.8.19;).",
        "references": ["https://swcregistry.io/docs/SWC-103"]
    },
    {
        "name": "Uninitialized Storage Pointer",
        "severity": Severity.HIGH,
        "swc": "SWC-109",
        "pattern": r'\b(struct|mapping)\b.*\bstorage\b(?!.*=)',
        "description": "Uninitialized storage pointer can overwrite existing storage slots unexpectedly.",
        "recommendation": "Always initialize storage variables. Use memory keyword for local variables.",
        "references": ["https://swcregistry.io/docs/SWC-109"]
    },
    {
        "name": "DoS with Gas Limit",
        "severity": Severity.MEDIUM,
        "swc": "SWC-128",
        "pattern": r'for\s*\(.*\.length',
        "description": "Unbounded loop over dynamic array can exceed block gas limit, causing denial of service.",
        "recommendation": "Implement pagination or pull-over-push patterns for array operations.",
        "references": ["https://swcregistry.io/docs/SWC-128"]
    },
    {
        "name": "Missing Event Emission",
        "severity": Severity.MEDIUM,
        "swc": "SWC-135",
        "pattern": r'(balances|balance|totalSupply)\s*[\+\-\*]?=',
        "context_check": lambda lines, idx: _check_missing_event(lines, idx),
        "description": "Critical state changes without event emission hinder off-chain monitoring and audit trails.",
        "recommendation": "Emit events for all critical state changes (transfers, balance updates, ownership changes).",
        "references": ["https://swcregistry.io/docs/SWC-135"]
    },
    {
        "name": "Hardcoded Address",
        "severity": Severity.LOW,
        "swc": "SWC-134",
        "pattern": r'0x[a-fA-F0-9]{40}',
        "description": "Hardcoded addresses reduce contract flexibility and may cause issues across different networks.",
        "recommendation": "Use constructor parameters or configuration functions for addresses.",
        "references": ["https://swcregistry.io/docs/SWC-134"]
    },
    {
        "name": "Use of send()",
        "severity": Severity.MEDIUM,
        "swc": "SWC-134",
        "pattern": r'\.send\s*\(',
        "description": "send() only forwards 2300 gas and returns bool. Can silently fail if recipient needs more gas.",
        "recommendation": "Use call{value: amount}('') with proper checks instead of send().",
        "references": ["https://swcregistry.io/docs/SWC-134"]
    },
    {
        "name": "Use of transfer()",
        "severity": Severity.LOW,
        "swc": "SWC-134",
        "pattern": r'\.transfer\s*\(',
        "description": "transfer() forwards only 2300 gas and reverts on failure. May break with EIP-1884 gas cost changes.",
        "recommendation": "Consider using call{value: amount}('') with reentrancy protection.",
        "references": ["https://swcregistry.io/docs/SWC-134"]
    },
]


# ─── Context Checkers ──────────────────────────────────────────────────

def _check_state_after_call(lines: List[str], idx: int) -> bool:
    """Check if there's a state change after an external call (reentrancy)."""
    for i in range(idx + 1, min(idx + 5, len(lines))):
        if re.search(r'\b\w+\[.*\]\s*[-+]?=', lines[i]):
            return True
        if re.search(r'\b(balances|balance|total)\b.*[-+]?=', lines[i]):
            return True
    return False


def _check_unchecked_return(lines: List[str], idx: int) -> bool:
    """Check if call return value is properly checked."""
    context = "\n".join(lines[max(0, idx - 2):idx + 3])
    return not re.search(r'(require|if|assert|bool)', context)


def _check_missing_access_control(lines: List[str], idx: int) -> bool:
    """Check if function has access control modifiers."""
    for i in range(max(0, idx - 10), idx):
        if re.search(r'(onlyOwner|require\s*\(\s*msg\.sender)', lines[i]):
            return False
    return True


def _check_missing_event(lines: List[str], idx: int) -> bool:
    """Check if nearby code emits an event."""
    for i in range(max(0, idx - 5), min(idx + 5, len(lines))):
        if re.search(r'emit\s+\w+', lines[i]):
            return False
    return True


# ─── Scanner Engine ────────────────────────────────────────────────────

class ShieldScanner:
    """Core vulnerability scanner engine."""

    def __init__(self):
        self.findings: List[Finding] = []

    def scan_file(self, filepath: str) -> List[Finding]:
        """Scan a Solidity file for vulnerabilities."""
        path = Path(filepath)
        if not path.exists():
            print(f"Error: File not found: {filepath}")
            sys.exit(1)
        if not path.suffix == '.sol':
            print(f"Warning: File does not have .sol extension: {filepath}")

        content = path.read_text(encoding='utf-8')
        return self.scan(content)

    def scan(self, source_code: str) -> List[Finding]:
        """Scan Solidity source code string for vulnerabilities."""
        self.findings = []
        lines = source_code.split('\n')

        for line_idx, line in enumerate(lines):
            stripped = line.strip()

            # Skip comments
            if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
                continue

            for pattern in PATTERNS:
                if re.search(pattern["pattern"], line):
                    # Run context check if defined
                    if "context_check" in pattern:
                        if not pattern["context_check"](lines, line_idx):
                            continue

                    finding = Finding(
                        name=pattern["name"],
                        severity=pattern["severity"],
                        description=pattern["description"],
                        line_number=line_idx + 1,
                        end_line=None,
                        code_snippet=stripped,
                        recommendation=pattern["recommendation"],
                        swc_id=pattern["swc"],
                        references=pattern.get("references", [])
                    )
                    self.findings.append(finding)

        return self.findings

    def get_summary(self) -> dict:
        """Get summary of scan results."""
        return {
            "total": len(self.findings),
            "critical": sum(1 for f in self.findings if f.severity == Severity.CRITICAL),
            "high": sum(1 for f in self.findings if f.severity == Severity.HIGH),
            "medium": sum(1 for f in self.findings if f.severity == Severity.MEDIUM),
            "low": sum(1 for f in self.findings if f.severity == Severity.LOW),
        }


# ─── Report Formatters ─────────────────────────────────────────────────

def format_text(scanner: ShieldScanner, filename: str, elapsed: float) -> str:
    """Format results as colored terminal output."""
    summary = scanner.get_summary()

    output = []
    output.append("")
    output.append("╔══════════════════════════════════════════════════════════════╗")
    output.append("║  ShieldScan — Smart Contract Vulnerability Scanner          ║")
    output.append("╚══════════════════════════════════════════════════════════════╝")
    output.append("")
    output.append(f"  Target: {filename}")
    output.append(f"  Patterns: {len(PATTERNS)} | Time: {elapsed:.2f}s")
    output.append("")
    output.append("  ┌─────────────────────────────────────────────────────────┐")
    output.append(f"  │  FINDINGS: {summary['total']} total" + " " * (47 - len(str(summary['total']))) + "│")
    output.append(f"  │  ● Critical: {summary['critical']}  ● High: {summary['high']}  ● Medium: {summary['medium']}  ○ Low: {summary['low']}" + " " * 6 + "│")
    output.append("  └─────────────────────────────────────────────────────────┘")
    output.append("")

    for f in scanner.findings:
        sev = f"[{f.severity.value}]"
        output.append(f"  {sev} {f.name} ({f.swc_id})")
        output.append(f"    Line {f.line_number} | {f.code_snippet[:60]}")
        output.append(f"    Fix: {f.recommendation[:70]}")
        output.append("")

    return "\n".join(output)


def format_json(scanner: ShieldScanner, filename: str, elapsed: float) -> str:
    """Format results as JSON."""
    return json.dumps({
        "tool": "ShieldScan",
        "version": "1.0.0",
        "target": filename,
        "scan_time": f"{elapsed:.2f}s",
        "summary": scanner.get_summary(),
        "findings": [f.to_dict() for f in scanner.findings]
    }, indent=2)


def format_evmbench(scanner: ShieldScanner, filename: str, elapsed: float) -> str:
    """Format results as EVMbench submission (audit.md with JSON block).

    Produces markdown containing a fenced JSON block conforming to the
    EVMbench ReportModel schema used by paradigmxyz/evmbench.
    """
    vulnerabilities = []
    for finding in scanner.findings:
        vuln = {
            "title": finding.name,
            "severity": finding.severity.value.lower(),
            "summary": finding.description,
            "description": [
                {
                    "file": filename,
                    "line_start": finding.line_number,
                    "line_end": finding.end_line if finding.end_line else finding.line_number,
                    "desc": f"{finding.name} ({finding.swc_id}): {finding.code_snippet}"
                }
            ],
            "impact": finding.description,
            "proof_of_concept": f"Detected at line {finding.line_number}: {finding.code_snippet}",
            "remediation": finding.recommendation
        }
        vulnerabilities.append(vuln)

    report = {"vulnerabilities": vulnerabilities}

    output = []
    output.append(f"# ShieldScan Audit Report — {filename}")
    output.append("")
    output.append(f"Scanner: ShieldScan v1.0.0 | Patterns: {len(PATTERNS)} | Time: {elapsed:.2f}s")
    output.append("")
    output.append("```json")
    output.append(json.dumps(report, indent=2))
    output.append("```")
    return "\n".join(output)


def format_markdown(scanner: ShieldScanner, filename: str, elapsed: float) -> str:
    """Format results as Markdown report."""
    summary = scanner.get_summary()
    output = []
    output.append(f"# ShieldScan Report — {filename}\n")
    output.append(f"**Scan Time:** {elapsed:.2f}s | **Patterns:** {len(PATTERNS)}\n")
    output.append("## Summary\n")
    output.append(f"| Severity | Count |")
    output.append(f"|---|---|")
    output.append(f"| 🔴 Critical | {summary['critical']} |")
    output.append(f"| 🟠 High | {summary['high']} |")
    output.append(f"| 🟡 Medium | {summary['medium']} |")
    output.append(f"| 🟢 Low | {summary['low']} |")
    output.append(f"| **Total** | **{summary['total']}** |")
    output.append("")
    output.append("## Findings\n")

    for i, f in enumerate(scanner.findings, 1):
        output.append(f"### {i}. {f.name} — `{f.severity.value}`\n")
        output.append(f"- **SWC:** {f.swc_id}")
        output.append(f"- **Line:** {f.line_number}")
        output.append(f"- **Description:** {f.description}")
        output.append(f"- **Code:** `{f.code_snippet}`")
        output.append(f"- **Recommendation:** {f.recommendation}")
        output.append("")

    return "\n".join(output)


# ─── CLI Entry Point ───────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="ShieldScan — Smart Contract Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("file", help="Path to Solidity (.sol) file to scan")
    parser.add_argument("-f", "--format", choices=["text", "json", "markdown", "evmbench"], default="text", help="Output format (evmbench produces submission/audit.md format)")
    parser.add_argument("-o", "--output", help="Output file path (default: stdout)")

    args = parser.parse_args()

    scanner = ShieldScanner()

    start = time.time()
    scanner.scan_file(args.file)
    elapsed = time.time() - start

    formatters = {
        "text": format_text,
        "json": format_json,
        "markdown": format_markdown,
        "evmbench": format_evmbench,
    }

    result = formatters[args.format](scanner, args.file, elapsed)

    if args.output:
        Path(args.output).write_text(result, encoding='utf-8')
        print(f"Report saved to {args.output}")
    else:
        print(result)


if __name__ == "__main__":
    main()
