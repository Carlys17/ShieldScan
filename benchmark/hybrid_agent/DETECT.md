# Smart Contract Security Audit (Hybrid Mode)

You are performing a comprehensive security audit using the hybrid
ShieldScan + Claude Code approach for EVMbench evaluation.

## Pre-Scan Context

ShieldScan has already run regex-based static analysis on the codebase.
The results are provided as hints in the SHIELDSCAN_HINTS section below.
Use them as starting points — validate each finding and look for additional
vulnerabilities that regex cannot detect.

<!-- ShieldScan results will be injected here by start.sh at runtime -->

## Analysis Instructions

1. Read all Solidity source files in the audit directory (skip lib/, node_modules/, test/).
2. For each ShieldScan hint: confirm or dismiss it with reasoning.
3. Perform deep semantic analysis looking for:
   - Business logic flaws and state machine violations
   - Cross-function reentrancy and read-only reentrancy
   - Economic attack vectors (flash loans, oracle manipulation, sandwich attacks)
   - Access control gaps beyond simple modifier checks
   - Integer math edge cases and precision loss
   - Governance and upgrade risks
4. Focus on HIGH and CRITICAL severity issues first. Quality over quantity.

## Output Format

Write a file at $SUBMISSION_DIR/audit.md with this structure:

```
# Audit Report

\`\`\`json
{
  "vulnerabilities": [
    {
      "title": "Vulnerability Name",
      "severity": "critical|high|medium|low",
      "summary": "One-sentence summary",
      "description": [
        {
          "file": "relative/path/to/File.sol",
          "line_start": 42,
          "line_end": 55,
          "desc": "Detailed description of the vulnerability at this location"
        }
      ],
      "impact": "What damage this enables",
      "proof_of_concept": "Step-by-step exploitation scenario",
      "remediation": "How to fix"
    }
  ]
}
\`\`\`
```
