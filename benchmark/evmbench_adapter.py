"""
EVMbench Adapter — Bidirectional conversion between ShieldScan findings
and EVMbench vulnerability formats, plus fuzzy matching for metrics.

Dependencies: pyyaml (for parsing EVMbench config.yaml files)
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from pathlib import Path


# ─── EVMbench Data Structures ──────────────────────────────────────────

@dataclass
class EVMbenchVulnerability:
    """A single vulnerability in EVMbench submission format."""
    title: str
    severity: str
    summary: str
    description: List[Dict[str, Any]]
    impact: str
    proof_of_concept: str = ""
    remediation: str = ""

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "severity": self.severity,
            "summary": self.summary,
            "description": self.description,
            "impact": self.impact,
            "proof_of_concept": self.proof_of_concept,
            "remediation": self.remediation,
        }


@dataclass
class EVMbenchReport:
    """Complete EVMbench submission report."""
    vulnerabilities: List[EVMbenchVulnerability]

    def to_dict(self) -> dict:
        return {"vulnerabilities": [v.to_dict() for v in self.vulnerabilities]}

    def to_audit_md(self, header: str = "") -> str:
        """Produce submission/audit.md content with fenced JSON block."""
        import json
        lines = []
        if header:
            lines.append(f"# {header}")
            lines.append("")
        lines.append("```json")
        lines.append(json.dumps(self.to_dict(), indent=2))
        lines.append("```")
        return "\n".join(lines)


# ─── Ground Truth ──────────────────────────────────────────────────────

@dataclass
class GroundTruthVulnerability:
    """A vulnerability from the EVMbench ground truth dataset."""
    id: str
    audit_id: str
    title: str
    findings_text: str
    award: float
    severity_bucket: str

    @property
    def keywords(self) -> List[str]:
        """Extract searchable keywords from title and findings text."""
        text = f"{self.title} {self.findings_text}".lower()
        # Common vulnerability keywords
        kw_patterns = [
            "reentrancy", "reentrant", "re-enter",
            "overflow", "underflow", "integer",
            "delegatecall", "selfdestruct", "suicide",
            "tx.origin", "access control", "unauthorized",
            "front-run", "frontrun", "sandwich",
            "oracle", "price manipulation",
            "flash loan", "flashloan",
            "unchecked", "return value",
            "timestamp", "block.timestamp",
            "dos", "denial of service", "gas limit",
            "storage", "uninitialized",
        ]
        found = []
        for kw in kw_patterns:
            if kw in text:
                found.append(kw)
        return found

    @property
    def mentioned_swc_ids(self) -> List[str]:
        """Extract SWC IDs mentioned in findings text."""
        return re.findall(r'SWC-\d+', self.findings_text)


def load_ground_truth(audit_dir: Path) -> List[GroundTruthVulnerability]:
    """Load ground truth vulnerabilities from an EVMbench audit directory.

    Reads config.yaml for vulnerability metadata and findings/*.md for
    full descriptions.
    """
    import yaml

    config_path = audit_dir / "config.yaml"
    if not config_path.exists():
        return []

    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    audit_id = config.get("id", audit_dir.name)

    vulns = []
    for v in config.get("vulnerabilities", []):
        vuln_id = v["id"]
        title = v.get("title", "")
        award = v.get("award", 0.0)

        if vuln_id.startswith("H"):
            severity = "high"
        elif vuln_id.startswith("M"):
            severity = "medium"
        else:
            severity = "low"

        findings_path = audit_dir / "findings" / f"{vuln_id}.md"
        findings_text = ""
        if findings_path.exists():
            findings_text = findings_path.read_text(encoding="utf-8")

        vulns.append(GroundTruthVulnerability(
            id=vuln_id,
            audit_id=audit_id,
            title=title,
            findings_text=findings_text,
            award=award,
            severity_bucket=severity,
        ))

    return vulns


# ─── Conversion ────────────────────────────────────────────────────────

def finding_to_evmbench(finding, source_file: str) -> EVMbenchVulnerability:
    """Convert a ShieldScan Finding to EVMbench vulnerability format."""
    return EVMbenchVulnerability(
        title=finding.name,
        severity=finding.severity.value.lower(),
        summary=finding.description,
        description=[{
            "file": source_file,
            "line_start": finding.line_number,
            "line_end": finding.end_line if finding.end_line else finding.line_number,
            "desc": f"{finding.name} ({finding.swc_id}): {finding.code_snippet}",
        }],
        impact=finding.description,
        proof_of_concept=f"Detected at line {finding.line_number}: {finding.code_snippet}",
        remediation=finding.recommendation,
    )


def findings_to_report(findings: list, source_file: str) -> EVMbenchReport:
    """Convert a list of ShieldScan Findings to a complete EVMbench report."""
    return EVMbenchReport(
        vulnerabilities=[finding_to_evmbench(f, source_file) for f in findings]
    )


# ─── Matching for Metrics ─────────────────────────────────────────────

# Map ShieldScan pattern names to searchable keywords for fuzzy matching
_PATTERN_KEYWORDS = {
    "Reentrancy Vulnerability": ["reentrancy", "reentrant", "re-enter", "external call"],
    "tx.origin Authentication": ["tx.origin", "phishing"],
    "Unchecked Call Return Value": ["unchecked", "return value", "low-level call"],
    "Delegatecall to Untrusted Contract": ["delegatecall", "proxy"],
    "Unprotected Selfdestruct": ["selfdestruct", "suicide", "destroy"],
    "Timestamp Dependence": ["timestamp", "block.timestamp", "miner"],
    "Block Number Dependence": ["block.number", "block number"],
    "Floating Pragma": ["pragma", "compiler version"],
    "Uninitialized Storage Pointer": ["storage", "uninitialized"],
    "DoS with Gas Limit": ["dos", "gas limit", "unbounded", "loop"],
    "Missing Event Emission": ["event", "emit", "monitoring"],
    "Hardcoded Address": ["hardcoded", "address"],
    "Use of send()": ["send", "2300 gas"],
    "Use of transfer()": ["transfer", "2300 gas"],
}


@dataclass
class MatchResult:
    """Result of matching ShieldScan findings against ground truth."""
    true_positives: List[Dict[str, Any]]
    false_positives: List[Any]
    false_negatives: List[GroundTruthVulnerability]


def _compute_keyword_overlap(finding_name: str, gt_vuln: GroundTruthVulnerability) -> float:
    """Compute keyword overlap score between a finding and ground truth."""
    pattern_kws = _PATTERN_KEYWORDS.get(finding_name, [])
    if not pattern_kws:
        return 0.0

    gt_text = f"{gt_vuln.title} {gt_vuln.findings_text}".lower()
    matches = sum(1 for kw in pattern_kws if kw in gt_text)
    return matches / len(pattern_kws) if pattern_kws else 0.0


def _check_swc_overlap(finding_swc: str, gt_vuln: GroundTruthVulnerability) -> bool:
    """Check if finding's SWC ID is mentioned in ground truth."""
    return finding_swc in gt_vuln.mentioned_swc_ids


def _check_file_overlap(finding_file: str, gt_vuln: GroundTruthVulnerability) -> bool:
    """Check if the finding's file is referenced in ground truth text."""
    if not finding_file:
        return False
    filename = Path(finding_file).name
    return filename.lower() in gt_vuln.findings_text.lower()


def match_findings_to_ground_truth(
    findings: list,
    ground_truth: List[GroundTruthVulnerability],
) -> MatchResult:
    """Match ShieldScan findings against EVMbench ground truth.

    Uses multiple heuristics since ShieldScan's regex patterns detect
    different vulnerability classes than EVMbench's real-world bugs.
    A match requires keyword overlap score >= 0.3 OR SWC-ID overlap.
    """
    matched_gt_ids = set()
    matched_finding_indices = set()
    true_positives = []

    # Score all (finding, gt_vuln) pairs
    pairs = []
    for f_idx, finding in enumerate(findings):
        for gt_vuln in ground_truth:
            score = 0.0

            # SWC overlap is a strong signal
            if _check_swc_overlap(finding.swc_id, gt_vuln):
                score += 0.5

            # Keyword overlap
            kw_score = _compute_keyword_overlap(finding.name, gt_vuln)
            score += kw_score * 0.4

            # File overlap adds a small bonus
            finding_file = ""
            if hasattr(finding, 'source_file'):
                finding_file = finding.source_file
            if _check_file_overlap(finding_file, gt_vuln):
                score += 0.1

            if score >= 0.3:
                pairs.append((score, f_idx, gt_vuln))

    # Greedy matching: best score first
    pairs.sort(key=lambda x: x[0], reverse=True)

    for score, f_idx, gt_vuln in pairs:
        if f_idx in matched_finding_indices or gt_vuln.id in matched_gt_ids:
            continue

        matched_finding_indices.add(f_idx)
        matched_gt_ids.add(gt_vuln.id)
        true_positives.append({
            "shieldscan_finding": findings[f_idx].name,
            "ground_truth_id": gt_vuln.id,
            "ground_truth_title": gt_vuln.title,
            "match_score": round(score, 3),
        })

    false_positives = [
        findings[i] for i in range(len(findings))
        if i not in matched_finding_indices
    ]
    false_negatives = [
        v for v in ground_truth
        if v.id not in matched_gt_ids
    ]

    return MatchResult(
        true_positives=true_positives,
        false_positives=false_positives,
        false_negatives=false_negatives,
    )
