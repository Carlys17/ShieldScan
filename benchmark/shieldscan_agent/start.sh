#!/bin/bash
set -euo pipefail

# ShieldScan agent startup script for EVMbench evaluation harness.
#
# EVMbench environment variables (set by the framework):
#   AGENT_DIR       - /home/agent
#   AUDIT_DIR       - /home/agent/audit
#   SUBMISSION_DIR  - /home/agent/submission
#   LOGS_DIR        - /home/logs

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[ShieldScan] Starting static analysis scan..."
echo "[ShieldScan] AUDIT_DIR=$AUDIT_DIR"
echo "[ShieldScan] SUBMISSION_DIR=$SUBMISSION_DIR"

mkdir -p "$SUBMISSION_DIR"

# Find all Solidity files (exclude lib/, node_modules/, test/)
SOL_FILES=$(find "$AUDIT_DIR" -name "*.sol" \
    -not -path "*/lib/*" \
    -not -path "*/node_modules/*" \
    -not -path "*/test/*" \
    -not -path "*/tests/*" \
    -not -path "*/.git/*" \
    -not -path "*/forge-std/*" \
    2>/dev/null | sort)

if [ -z "$SOL_FILES" ]; then
    echo "[ShieldScan] No .sol files found in $AUDIT_DIR"
    cat > "$SUBMISSION_DIR/audit.md" <<'EMPTY'
# ShieldScan Audit Report

```json
{"vulnerabilities": []}
```
EMPTY
    exit 0
fi

FILE_COUNT=$(echo "$SOL_FILES" | wc -l)
echo "[ShieldScan] Found $FILE_COUNT Solidity files"

# Scan each file and collect JSON outputs
TEMP_DIR=$(mktemp -d)
INDEX=0

for SOL_FILE in $SOL_FILES; do
    REL_PATH=$(realpath --relative-to="$AUDIT_DIR" "$SOL_FILE" 2>/dev/null || echo "$SOL_FILE")
    echo "[ShieldScan] Scanning: $REL_PATH"

    python3 "$SCRIPT_DIR/scanner.py" "$SOL_FILE" -f json -o "$TEMP_DIR/scan_$INDEX.json" \
        2>&1 | tee -a "${LOGS_DIR:-/tmp}/shieldscan.log" || true

    INDEX=$((INDEX + 1))
done

# Aggregate all scan results into single EVMbench submission
python3 "$SCRIPT_DIR/aggregate.py" \
    --scan-dir "$TEMP_DIR" \
    --audit-dir "$AUDIT_DIR" \
    --output "$SUBMISSION_DIR/audit.md" \
    2>&1 | tee -a "${LOGS_DIR:-/tmp}/shieldscan.log"

rm -rf "$TEMP_DIR"

echo "[ShieldScan] Scan complete. Submission written to $SUBMISSION_DIR/audit.md"
