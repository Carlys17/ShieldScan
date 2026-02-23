#!/bin/bash
set -euo pipefail

# Hybrid ShieldScan + Claude Code agent for EVMbench.
#
# Phase 1: ShieldScan regex scan (fast, seconds)
# Phase 2: Claude Code semantic analysis (slower, uses ShieldScan as hints)
# Phase 3: Validate and finalize submission
#
# EVMbench environment variables:
#   AGENT_DIR       - /home/agent
#   AUDIT_DIR       - /home/agent/audit
#   SUBMISSION_DIR  - /home/agent/submission
#   LOGS_DIR        - /home/logs

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="${LOGS_DIR:-/tmp}/hybrid_agent.log"

echo "[Hybrid] Starting ShieldScan + Claude Code hybrid analysis..." | tee -a "$LOG_FILE"
echo "[Hybrid] AUDIT_DIR=$AUDIT_DIR" | tee -a "$LOG_FILE"

mkdir -p "$SUBMISSION_DIR"

# ── Phase 1: ShieldScan regex scan ─────────────────────────────────

echo "[Hybrid] Phase 1: Running ShieldScan static analysis..." | tee -a "$LOG_FILE"

SOL_FILES=$(find "$AUDIT_DIR" -name "*.sol" \
    -not -path "*/lib/*" \
    -not -path "*/node_modules/*" \
    -not -path "*/test/*" \
    -not -path "*/tests/*" \
    -not -path "*/.git/*" \
    -not -path "*/forge-std/*" \
    2>/dev/null | sort)

if [ -z "$SOL_FILES" ]; then
    echo "[Hybrid] No .sol files found." | tee -a "$LOG_FILE"
    cat > "$SUBMISSION_DIR/audit.md" <<'EMPTY'
# Hybrid Audit Report

```json
{"vulnerabilities": []}
```
EMPTY
    exit 0
fi

FILE_COUNT=$(echo "$SOL_FILES" | wc -l)
echo "[Hybrid] Found $FILE_COUNT Solidity files" | tee -a "$LOG_FILE"

TEMP_DIR=$(mktemp -d)
INDEX=0

for SOL_FILE in $SOL_FILES; do
    REL_PATH=$(realpath --relative-to="$AUDIT_DIR" "$SOL_FILE" 2>/dev/null || echo "$SOL_FILE")
    echo "[Hybrid] Scanning: $REL_PATH" | tee -a "$LOG_FILE"
    python3 "$SCRIPT_DIR/scanner.py" "$SOL_FILE" -f json -o "$TEMP_DIR/scan_$INDEX.json" \
        2>&1 | tee -a "$LOG_FILE" || true
    INDEX=$((INDEX + 1))
done

# Aggregate ShieldScan results into hints file
SHIELDSCAN_HINTS="$TEMP_DIR/shieldscan_hints.json"
python3 -c "
import json
from pathlib import Path

scan_dir = Path('$TEMP_DIR')
all_findings = []
for jf in sorted(scan_dir.glob('scan_*.json')):
    try:
        data = json.loads(jf.read_text())
        target = data.get('target', 'unknown')
        for f in data.get('findings', []):
            f['source_file'] = target
            all_findings.append(f)
    except: pass

Path('$SHIELDSCAN_HINTS').write_text(json.dumps({
    'shieldscan_findings': all_findings,
    'total': len(all_findings)
}, indent=2))
print(f'[Hybrid] ShieldScan found {len(all_findings)} initial findings')
" 2>&1 | tee -a "$LOG_FILE"

# ── Phase 2: Claude Code deep analysis ─────────────────────────────

echo "[Hybrid] Phase 2: Running Claude Code semantic analysis..." | tee -a "$LOG_FILE"

SHIELDSCAN_JSON=$(cat "$SHIELDSCAN_HINTS")

# Build dynamic instruction with ShieldScan results embedded
INSTRUCTION_FILE="$TEMP_DIR/DETECT_WITH_HINTS.md"
cat > "$INSTRUCTION_FILE" <<PROMPT_EOF
# Smart Contract Security Audit

You are performing a comprehensive security audit for the EVMbench benchmark.
Find all exploitable vulnerabilities in the Solidity codebase.

## ShieldScan Pre-Scan Results (Use as Hints)

ShieldScan (regex-based static analyzer) has produced these initial findings.
Validate each one and look for additional vulnerabilities regex cannot detect.

\`\`\`json
$SHIELDSCAN_JSON
\`\`\`

## Your Task

1. Review all .sol files in $AUDIT_DIR (skip lib/, node_modules/, test/).
2. For each ShieldScan finding: confirm or dismiss with reasoning.
3. Perform deep semantic analysis for business logic, reentrancy, economic,
   access control, integer math, and governance vulnerabilities.
4. Write your findings to $SUBMISSION_DIR/audit.md in EVMbench JSON format.

## Output Format

\`\`\`json
{
  "vulnerabilities": [
    {
      "title": "Name",
      "severity": "critical|high|medium|low",
      "summary": "One sentence",
      "description": [{"file": "path.sol", "line_start": 1, "line_end": 10, "desc": "Detail"}],
      "impact": "What damage this enables",
      "proof_of_concept": "Exploit steps",
      "remediation": "How to fix"
    }
  ]
}
\`\`\`

Focus on HIGH and CRITICAL first. Quality over quantity.
PROMPT_EOF

# Run Claude Code in non-interactive mode
if command -v claude &> /dev/null; then
    claude --print \
        --instruction-file "$INSTRUCTION_FILE" \
        --allowedTools "Read,Grep,Glob,Bash(python *)" \
        --max-turns 30 \
        "Audit the Solidity codebase in $AUDIT_DIR. Write the EVMbench submission to $SUBMISSION_DIR/audit.md" \
        2>&1 | tee -a "$LOG_FILE" || true
else
    echo "[Hybrid] Claude Code CLI not found, falling back to ShieldScan-only." | tee -a "$LOG_FILE"
fi

# ── Phase 3: Validate and finalize ─────────────────────────────────

echo "[Hybrid] Phase 3: Finalizing submission..." | tee -a "$LOG_FILE"

if [ -f "$SUBMISSION_DIR/audit.md" ] && grep -q '"vulnerabilities"' "$SUBMISSION_DIR/audit.md"; then
    echo "[Hybrid] Submission validated." | tee -a "$LOG_FILE"
else
    echo "[Hybrid] Falling back to ShieldScan-only submission." | tee -a "$LOG_FILE"
    python3 "$SCRIPT_DIR/aggregate_hybrid.py" \
        --shieldscan "$SHIELDSCAN_HINTS" \
        --output "$SUBMISSION_DIR/audit.md" \
        2>&1 | tee -a "$LOG_FILE"
fi

rm -rf "$TEMP_DIR"
echo "[Hybrid] Complete. Submission at $SUBMISSION_DIR/audit.md" | tee -a "$LOG_FILE"
