---
name: security-scan
description: Scan Solidity smart contracts for vulnerabilities using ShieldScan static analysis combined with AI-powered semantic review
argument-hint: [file.sol or directory]
allowed-tools: Read, Grep, Glob, Bash(python *)
---

# Security Scan Skill

You are performing a comprehensive security audit of Solidity smart contracts.
You combine ShieldScan's regex-based static analysis with deep semantic reasoning.

## Input

The user provides a file path or directory path as the argument. If no argument
is given, scan the current working directory for all `.sol` files.

## Step 1: Run ShieldScan Static Analysis

Run ShieldScan on the target:

**If scanning a single file:**
```bash
python src/scanner.py <target_file> -f json
```

**If scanning a directory:**
```bash
find <target_dir> -name "*.sol" -not -path "*/lib/*" -not -path "*/node_modules/*" -not -path "*/test/*" -not -path "*/.git/*" -not -path "*/forge-std/*" | while read f; do
  echo "=== FILE: $f ==="
  python src/scanner.py "$f" -f json
done
```

Parse the JSON output to get the list of ShieldScan findings.

## Step 2: Read Source Code

Read the source code of every scanned file using the Read tool. You need the
full source for semantic analysis in Step 3.

## Step 3: AI Semantic Analysis

Analyze the source code beyond what regex can detect. Specifically look for:

1. **Business Logic Vulnerabilities**
   - Functions that can be called in an unintended order
   - Missing validation on critical parameters
   - State machine violations
   - Incorrect access control boundaries (not just missing modifiers)

2. **Cross-Function Data Flow Issues**
   - State variables modified in one function and read unsafely in another
   - Storage slot collisions in proxy patterns
   - Incorrect inheritance linearization

3. **Economic / DeFi Vulnerabilities**
   - Price oracle manipulation (stale prices, single-source oracles)
   - Flash loan attack vectors
   - Sandwich attack susceptibility
   - Rounding errors in token math that accumulate
   - Inflation/deflation attack on vault shares (first depositor attack)

4. **Reentrancy Beyond Regex**
   - Cross-function reentrancy (function A calls external, function B reads dirty state)
   - Read-only reentrancy (view functions returning stale data during callback)
   - Cross-contract reentrancy

5. **Governance & Upgrade Risks**
   - Unprotected initializer functions
   - Storage layout incompatibility between upgrade versions
   - Centralization risks (single admin key)

6. **Gas & DoS**
   - Unbounded loops not caught by regex (while loops, recursive calls)
   - External calls in loops
   - Block gas limit exhaustion via return data bombs

For each AI-discovered issue, assign a confidence level:
- **High Confidence**: The issue is clearly present in the code
- **Medium Confidence**: The issue likely exists but depends on external context
- **Low Confidence**: Potential concern that needs manual verification

## Step 4: Cross-Reference and Validate

For each ShieldScan regex finding:
- Confirm or dismiss it based on your semantic understanding
- If a regex finding is a **false positive**, explain why
- If a regex finding is **confirmed**, add additional context about exploitability

## Step 5: Generate Combined Report

Output a structured report in this format:

```
## Security Scan Report: <target>

### Summary
- ShieldScan findings: N (X confirmed, Y false positives)
- AI-discovered issues: M
- Overall risk: CRITICAL / HIGH / MEDIUM / LOW

### Critical & High Findings

#### [CONFIRMED] <Finding Name> (ShieldScan + AI)
- **Severity**: CRITICAL
- **Location**: file.sol:L42
- **ShieldScan Detection**: SWC-107 reentrancy pattern
- **AI Analysis**: <deeper explanation of exploitability>
- **Recommendation**: <specific fix>

#### [AI-DISCOVERED] <Finding Name>
- **Severity**: HIGH
- **Confidence**: High
- **Location**: file.sol:L88-L95
- **Description**: <what the issue is and why it matters>
- **Attack Scenario**: <step-by-step how this could be exploited>
- **Recommendation**: <specific fix>

### Medium & Low Findings
(same format)

### Dismissed ShieldScan Findings
- <Finding at line N>: False positive because <reason>

### Methodology
Static analysis via ShieldScan (14 regex patterns) combined with
AI semantic review covering business logic, data flow, economic
attack vectors, and cross-function analysis.
```

## Important Notes

- Always run ShieldScan first. Its findings serve as starting points.
- Do not simply repeat ShieldScan findings. Add value through deeper analysis.
- Be honest about confidence levels. Do not inflate severity.
- If a contract looks secure, say so. Not every scan produces findings.
