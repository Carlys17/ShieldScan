#!/usr/bin/env python3
"""
EVMbench Runner — Benchmark ShieldScan against the EVMbench dataset.

Usage:
    python benchmark/evmbench_runner.py [--config benchmark/config.yaml]
    python benchmark/evmbench_runner.py --audit-id 2023-07-pooltogether
    python benchmark/evmbench_runner.py --audits-dir /path/to/evmbench/audits

Dependencies: pyyaml, requests
"""

import argparse
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List, Dict, Optional

# Add parent src/ to path for ShieldScan imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from scanner import ShieldScanner, Finding, Severity

from evmbench_adapter import (
    load_ground_truth,
    match_findings_to_ground_truth,
    findings_to_report,
    MatchResult,
    GroundTruthVulnerability,
)


# ─── Configuration ─────────────────────────────────────────────────────

@dataclass
class BenchmarkConfig:
    """Configuration for a benchmark run."""
    evmbench_repo: str = "openai/frontier-evals"
    audits_subpath: str = "project/evmbench/audits"
    audits_dir: Optional[str] = None
    output_dir: str = "benchmark/results"
    clone_repos: bool = True
    audit_ids: Optional[List[str]] = None
    task_info_csv: Optional[str] = None

    @classmethod
    def from_yaml(cls, path: str) -> "BenchmarkConfig":
        import yaml
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        valid_fields = cls.__dataclass_fields__
        return cls(**{k: v for k, v in data.items() if k in valid_fields})


# ─── Metrics ───────────────────────────────────────────────────────────

@dataclass
class AuditMetrics:
    """Metrics for a single audit."""
    audit_id: str
    total_ground_truth: int
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1: float
    scan_time_seconds: float
    shieldscan_findings_count: int
    files_scanned: int
    match_details: List[Dict]

    @staticmethod
    def compute(
        audit_id: str,
        match_result: MatchResult,
        total_findings: int,
        scan_time: float,
        files_scanned: int,
    ) -> "AuditMetrics":
        tp = len(match_result.true_positives)
        fp = len(match_result.false_positives)
        fn = len(match_result.false_negatives)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

        return AuditMetrics(
            audit_id=audit_id,
            total_ground_truth=tp + fn,
            true_positives=tp,
            false_positives=fp,
            false_negatives=fn,
            precision=round(precision, 4),
            recall=round(recall, 4),
            f1=round(f1, 4),
            scan_time_seconds=round(scan_time, 3),
            shieldscan_findings_count=total_findings,
            files_scanned=files_scanned,
            match_details=list(match_result.true_positives),
        )

    def to_dict(self) -> dict:
        return {
            "audit_id": self.audit_id,
            "total_ground_truth": self.total_ground_truth,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
            "scan_time_seconds": self.scan_time_seconds,
            "shieldscan_findings_count": self.shieldscan_findings_count,
            "files_scanned": self.files_scanned,
            "match_details": self.match_details,
        }


@dataclass
class AggregateMetrics:
    """Aggregate metrics across all audits."""
    total_audits: int
    total_vulnerabilities: int
    total_true_positives: int
    total_false_positives: int
    total_false_negatives: int
    macro_precision: float
    macro_recall: float
    macro_f1: float
    micro_precision: float
    micro_recall: float
    micro_f1: float
    total_scan_time: float
    per_audit: List[AuditMetrics]

    @staticmethod
    def from_audit_metrics(metrics: List[AuditMetrics]) -> "AggregateMetrics":
        if not metrics:
            return AggregateMetrics(
                total_audits=0, total_vulnerabilities=0,
                total_true_positives=0, total_false_positives=0,
                total_false_negatives=0,
                macro_precision=0, macro_recall=0, macro_f1=0,
                micro_precision=0, micro_recall=0, micro_f1=0,
                total_scan_time=0, per_audit=[],
            )

        total_tp = sum(m.true_positives for m in metrics)
        total_fp = sum(m.false_positives for m in metrics)
        total_fn = sum(m.false_negatives for m in metrics)

        micro_p = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0
        micro_r = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0.0
        micro_f1 = 2 * micro_p * micro_r / (micro_p + micro_r) if (micro_p + micro_r) > 0 else 0.0

        valid = [m for m in metrics if m.total_ground_truth > 0]
        macro_p = sum(m.precision for m in valid) / len(valid) if valid else 0.0
        macro_r = sum(m.recall for m in valid) / len(valid) if valid else 0.0
        macro_f1 = sum(m.f1 for m in valid) / len(valid) if valid else 0.0

        return AggregateMetrics(
            total_audits=len(metrics),
            total_vulnerabilities=sum(m.total_ground_truth for m in metrics),
            total_true_positives=total_tp,
            total_false_positives=total_fp,
            total_false_negatives=total_fn,
            macro_precision=round(macro_p, 4),
            macro_recall=round(macro_r, 4),
            macro_f1=round(macro_f1, 4),
            micro_precision=round(micro_p, 4),
            micro_recall=round(micro_r, 4),
            micro_f1=round(micro_f1, 4),
            total_scan_time=round(sum(m.scan_time_seconds for m in metrics), 3),
            per_audit=metrics,
        )

    def to_dict(self) -> dict:
        return {
            "total_audits": self.total_audits,
            "total_vulnerabilities": self.total_vulnerabilities,
            "total_true_positives": self.total_true_positives,
            "total_false_positives": self.total_false_positives,
            "total_false_negatives": self.total_false_negatives,
            "macro_precision": self.macro_precision,
            "macro_recall": self.macro_recall,
            "macro_f1": self.macro_f1,
            "micro_precision": self.micro_precision,
            "micro_recall": self.micro_recall,
            "micro_f1": self.micro_f1,
            "total_scan_time": self.total_scan_time,
            "per_audit": [m.to_dict() for m in self.per_audit],
        }


# ─── Dataset Fetching ──────────────────────────────────────────────────

def fetch_evmbench_audits(config: BenchmarkConfig) -> Path:
    """Fetch the EVMbench audits directory.

    If audits_dir is set in config, use that path directly.
    Otherwise, do a sparse clone of the frontier-evals repo to get only
    the audits/ directory.
    """
    if config.audits_dir:
        p = Path(config.audits_dir)
        if p.exists():
            return p
        print(f"Error: audits_dir not found: {config.audits_dir}")
        sys.exit(1)

    cache_dir = Path(config.output_dir).parent / ".evmbench_cache"
    audits_path = cache_dir / config.audits_subpath

    if audits_path.exists():
        print(f"Using cached EVMbench audits at {audits_path}")
        return audits_path

    print(f"Cloning EVMbench audits from {config.evmbench_repo}...")
    cache_dir.mkdir(parents=True, exist_ok=True)

    repo_url = f"https://github.com/{config.evmbench_repo}.git"
    clone_dir = cache_dir / "frontier-evals"

    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--filter=blob:none",
             "--sparse", repo_url, str(clone_dir)],
            check=True, capture_output=True, text=True,
        )
        subprocess.run(
            ["git", "sparse-checkout", "set", config.audits_subpath],
            cwd=str(clone_dir), check=True, capture_output=True, text=True,
        )
    except subprocess.CalledProcessError as e:
        print(f"Error cloning EVMbench: {e.stderr}")
        sys.exit(1)
    except FileNotFoundError:
        print("Error: git is not installed. Install git or set audits_dir in config.")
        sys.exit(1)

    actual = clone_dir / config.audits_subpath
    if actual.exists():
        return actual

    print(f"Error: audits path not found after clone: {actual}")
    sys.exit(1)


def clone_audit_repo(audit_id: str, config_yaml: dict, dest_dir: Path) -> Optional[Path]:
    """Clone an audit's source repository at its base_commit.

    EVMbench audits reference repos from evmbench-org/ GitHub mirrors.
    Returns the cloned repo path, or None on failure.
    """
    base_commit = config_yaml.get("base_commit")
    if not base_commit:
        return None

    repo_name = audit_id.replace("-", "_")
    repo_url = f"https://github.com/evmbench-org/{repo_name}.git"

    repo_dir = dest_dir / audit_id
    if repo_dir.exists():
        return repo_dir

    try:
        subprocess.run(
            ["git", "clone", "--depth", "50", repo_url, str(repo_dir)],
            check=True, capture_output=True, text=True, timeout=120,
        )
        subprocess.run(
            ["git", "checkout", base_commit],
            cwd=str(repo_dir), check=True, capture_output=True, text=True,
        )
        return repo_dir
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"  Warning: Could not clone repo for {audit_id}: {e}")
        return None


def find_solidity_files(directory: Path) -> List[Path]:
    """Find all .sol files, excluding lib/, node_modules/, test/, .git/."""
    excluded = {"lib", "node_modules", "test", "tests", ".git", "forge-std"}
    sol_files = []
    for sol_file in directory.rglob("*.sol"):
        parts = sol_file.relative_to(directory).parts
        if any(p in excluded for p in parts):
            continue
        sol_files.append(sol_file)
    return sorted(sol_files)


# ─── Benchmark Execution ──────────────────────────────────────────────

def scan_audit(
    audit_id: str,
    audit_dir: Path,
    ground_truth: List[GroundTruthVulnerability],
    config: BenchmarkConfig,
    repos_dir: Path,
    verbose: bool = False,
) -> Optional[AuditMetrics]:
    """Run ShieldScan against a single audit and compute metrics."""
    import yaml

    config_path = audit_dir / "config.yaml"
    if not config_path.exists():
        print(f"  Skipping {audit_id}: no config.yaml")
        return None

    audit_config = yaml.safe_load(config_path.read_text(encoding="utf-8"))

    # Try to get source code
    sol_files = []
    repo_dir = None

    if config.clone_repos:
        repo_dir = clone_audit_repo(audit_id, audit_config, repos_dir)
        if repo_dir:
            sol_files = find_solidity_files(repo_dir)

    # If no repo cloned, scan any .sol files in the audit dir itself
    if not sol_files:
        sol_files = find_solidity_files(audit_dir)

    if not sol_files:
        print(f"  Skipping {audit_id}: no .sol files found")
        return None

    # Scan all files
    all_findings: List[Finding] = []

    start_time = time.time()
    for sol_file in sol_files:
        try:
            source = sol_file.read_text(encoding="utf-8")
            findings = ShieldScanner().scan(source)
            # Tag findings with source file
            for f in findings:
                f.source_file = str(sol_file.relative_to(repo_dir or audit_dir))
            all_findings.extend(findings)
        except Exception as e:
            if verbose:
                print(f"    Error scanning {sol_file.name}: {e}")
    elapsed = time.time() - start_time

    if verbose:
        print(f"  Scanned {len(sol_files)} files, found {len(all_findings)} findings in {elapsed:.2f}s")

    # Match against ground truth
    match_result = match_findings_to_ground_truth(all_findings, ground_truth)

    return AuditMetrics.compute(
        audit_id=audit_id,
        match_result=match_result,
        total_findings=len(all_findings),
        scan_time=elapsed,
        files_scanned=len(sol_files),
    )


def run_benchmark(config: BenchmarkConfig, verbose: bool = False) -> AggregateMetrics:
    """Execute the full benchmark pipeline."""
    import yaml

    audits_dir = fetch_evmbench_audits(config)
    output_dir = Path(config.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    repos_dir = output_dir.parent / ".evmbench_repos"
    repos_dir.mkdir(parents=True, exist_ok=True)

    # Discover audits
    audit_dirs = sorted([
        d for d in audits_dir.iterdir()
        if d.is_dir() and (d / "config.yaml").exists() and d.name != "template"
    ])

    if config.audit_ids:
        audit_dirs = [d for d in audit_dirs if d.name in config.audit_ids]

    if not audit_dirs:
        print("No audits found to benchmark.")
        return AggregateMetrics.from_audit_metrics([])

    print(f"Found {len(audit_dirs)} audits to benchmark")
    print("=" * 60)

    all_metrics: List[AuditMetrics] = []

    for i, audit_dir in enumerate(audit_dirs, 1):
        audit_id = audit_dir.name
        print(f"\n[{i}/{len(audit_dirs)}] {audit_id}")

        ground_truth = load_ground_truth(audit_dir)
        if not ground_truth:
            print(f"  Skipping: no ground truth vulnerabilities")
            continue

        print(f"  Ground truth: {len(ground_truth)} vulnerabilities")

        metrics = scan_audit(
            audit_id=audit_id,
            audit_dir=audit_dir,
            ground_truth=ground_truth,
            config=config,
            repos_dir=repos_dir,
            verbose=verbose,
        )

        if metrics:
            all_metrics.append(metrics)
            print(f"  Results: TP={metrics.true_positives} FP={metrics.false_positives} "
                  f"FN={metrics.false_negatives} P={metrics.precision:.2%} R={metrics.recall:.2%}")

            # Write per-audit results
            audit_output = output_dir / audit_id
            audit_output.mkdir(parents=True, exist_ok=True)
            (audit_output / "metrics.json").write_text(
                json.dumps(metrics.to_dict(), indent=2), encoding="utf-8"
            )

    return AggregateMetrics.from_audit_metrics(all_metrics)


# ─── Report Generation ────────────────────────────────────────────────

def generate_report(metrics: AggregateMetrics, output_dir: Path) -> None:
    """Generate benchmark results in JSON and Markdown."""
    output_dir.mkdir(parents=True, exist_ok=True)

    # JSON summary
    (output_dir / "summary.json").write_text(
        json.dumps(metrics.to_dict(), indent=2), encoding="utf-8"
    )

    # Markdown summary
    md = []
    md.append("# ShieldScan EVMbench Benchmark Results\n")
    md.append(f"**Audits evaluated:** {metrics.total_audits}")
    md.append(f"**Ground truth vulnerabilities:** {metrics.total_vulnerabilities}")
    md.append(f"**Total scan time:** {metrics.total_scan_time:.1f}s\n")

    md.append("## Aggregate Metrics\n")
    md.append("| Metric | Micro | Macro |")
    md.append("|--------|-------|-------|")
    md.append(f"| Precision | {metrics.micro_precision:.2%} | {metrics.macro_precision:.2%} |")
    md.append(f"| Recall | {metrics.micro_recall:.2%} | {metrics.macro_recall:.2%} |")
    md.append(f"| F1 Score | {metrics.micro_f1:.2%} | {metrics.macro_f1:.2%} |")
    md.append("")

    md.append("| Count | Value |")
    md.append("|-------|-------|")
    md.append(f"| True Positives | {metrics.total_true_positives} |")
    md.append(f"| False Positives | {metrics.total_false_positives} |")
    md.append(f"| False Negatives | {metrics.total_false_negatives} |")
    md.append("")

    md.append("## Per-Audit Results\n")
    md.append("| Audit | GT | TP | FP | FN | P | R | F1 | Files | Time |")
    md.append("|-------|----|----|----|----|---|---|----|-------|------|")
    for m in metrics.per_audit:
        md.append(
            f"| {m.audit_id} | {m.total_ground_truth} | {m.true_positives} | "
            f"{m.false_positives} | {m.false_negatives} | {m.precision:.0%} | "
            f"{m.recall:.0%} | {m.f1:.2f} | {m.files_scanned} | {m.scan_time_seconds:.1f}s |"
        )
    md.append("")

    # Match details
    has_matches = any(m.match_details for m in metrics.per_audit)
    if has_matches:
        md.append("## Match Details\n")
        for m in metrics.per_audit:
            if m.match_details:
                md.append(f"### {m.audit_id}\n")
                for d in m.match_details:
                    md.append(
                        f"- **{d['shieldscan_finding']}** matched "
                        f"**{d['ground_truth_id']}**: {d['ground_truth_title']} "
                        f"(score: {d['match_score']:.2f})"
                    )
                md.append("")

    md.append("\n---\n")
    md.append("*Generated by ShieldScan EVMbench Runner*")

    (output_dir / "summary.md").write_text("\n".join(md), encoding="utf-8")
    print(f"\nReports saved to {output_dir}/")


# ─── CLI ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Benchmark ShieldScan against EVMbench dataset"
    )
    parser.add_argument("--config", default="benchmark/config.yaml",
                        help="Path to benchmark configuration YAML")
    parser.add_argument("--audits-dir",
                        help="Local path to EVMbench audits directory")
    parser.add_argument("--output-dir", default="benchmark/results",
                        help="Directory for benchmark results")
    parser.add_argument("--audit-id", action="append",
                        help="Run only specific audit(s). Can be repeated.")
    parser.add_argument("--no-clone", action="store_true",
                        help="Skip cloning source repos (scan audit dir only)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose output")

    args = parser.parse_args()

    # Load config
    config_path = Path(args.config)
    if config_path.exists():
        config = BenchmarkConfig.from_yaml(str(config_path))
    else:
        config = BenchmarkConfig()

    # Apply CLI overrides
    if args.audits_dir:
        config.audits_dir = args.audits_dir
    if args.output_dir:
        config.output_dir = args.output_dir
    if args.audit_id:
        config.audit_ids = args.audit_id
    if args.no_clone:
        config.clone_repos = False

    # Run benchmark
    metrics = run_benchmark(config, verbose=args.verbose)
    generate_report(metrics, Path(config.output_dir))

    # Print summary
    print(f"\n{'=' * 60}")
    print(f"EVMbench Benchmark Results for ShieldScan")
    print(f"{'=' * 60}")
    print(f"Audits evaluated:           {metrics.total_audits}")
    print(f"Ground truth vulns:         {metrics.total_vulnerabilities}")
    print(f"True positives:             {metrics.total_true_positives}")
    print(f"False positives:            {metrics.total_false_positives}")
    print(f"False negatives:            {metrics.total_false_negatives}")
    print(f"Micro precision:            {metrics.micro_precision:.2%}")
    print(f"Micro recall:               {metrics.micro_recall:.2%}")
    print(f"Micro F1:                   {metrics.micro_f1:.2%}")
    print(f"Total scan time:            {metrics.total_scan_time:.1f}s")


if __name__ == "__main__":
    main()
