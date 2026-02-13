<p align="center">
  <img src="docs/logo.svg" alt="ShieldScan Logo" width="80" />
</p>

<h1 align="center">ShieldScan</h1>

<p align="center">
  <strong>Open-source smart contract vulnerability scanner for the Web3 community.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/license-MIT-yellow?style=flat-square" alt="License" />
  <img src="https://img.shields.io/badge/solidity-%5E0.8.x-363636?style=flat-square&logo=solidity" alt="Solidity" />
  <img src="https://img.shields.io/badge/python-3.9+-3776ab?style=flat-square&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/react-18+-61dafb?style=flat-square&logo=react&logoColor=black" alt="React" />
  <img src="https://img.shields.io/badge/chains-100+-FFB800?style=flat-square" alt="Chains" />
</p>

<p align="center">
  <img src="docs/screenshot.png" alt="ShieldScan Screenshot" width="800" />
</p>

---

## Overview

ShieldScan is a security-first tool that scans Solidity smart contracts for common vulnerabilities, helping developers and auditors identify critical issues before deployment. Available as both a **Python CLI tool** and an **interactive web application**.

Built with the principle that **robust security defenses belong in the hands of individuals** — not locked behind expensive audit firms.

## Features

- **14+ Vulnerability Patterns** — Reentrancy, tx.origin, unchecked calls, integer overflow, and more
- **SWC Registry Mapped** — Every finding linked to the Smart Contract Weakness Classification
- **Severity Classification** — Critical, High, Medium, Low with actionable fix recommendations
- **Multi-Format Output** — JSON, Markdown, and interactive HTML reports
- **Web UI** — Paste code and scan instantly in the browser
- **CLI Tool** — Integrate into CI/CD pipelines and development workflows
- **100% Open Source** — MIT licensed, free forever

## Quick Start

### Web App (No Install)

Open `public/index.html` in your browser — paste Solidity code and scan instantly.

### Python CLI

```bash
# Clone the repository
git clone https://github.com/Carlys17/ShieldScan.git
cd ShieldScan

# Install dependencies
pip install -r requirements.txt

# Scan a contract
python src/scanner.py examples/VulnerableVault.sol

# Output as JSON
python src/scanner.py examples/VulnerableVault.sol -f json

# Output as Markdown report
python src/scanner.py examples/VulnerableVault.sol -f markdown -o report.md
```

## Vulnerability Patterns

| ID | Pattern | Severity | SWC |
|---|---|---|---|
| 01 | Reentrancy | Critical | SWC-107 |
| 02 | tx.origin Authentication | High | SWC-115 |
| 03 | Unchecked Call Return | High | SWC-104 |
| 04 | Delegatecall to Untrusted | Critical | SWC-112 |
| 05 | Unprotected selfdestruct | Critical | SWC-106 |
| 06 | Integer Overflow/Underflow | High | SWC-101 |
| 07 | Timestamp Dependence | Medium | SWC-116 |
| 08 | Block Number Dependence | Low | SWC-120 |
| 09 | Missing Access Control | Medium | SWC-105 |
| 10 | Floating Pragma | Low | SWC-103 |
| 11 | Uninitialized Storage | High | SWC-109 |
| 12 | DoS with Gas Limit | Medium | SWC-128 |
| 13 | Missing Event Emission | Medium | SWC-135 |
| 14 | Hardcoded Addresses | Low | SWC-134 |

## Project Structure

```
ShieldScan/
├── src/
│   ├── scanner.py          # Core vulnerability scanner engine
│   ├── patterns.py         # Vulnerability pattern definitions
│   ├── reporter.py         # Report generation (JSON/MD/HTML)
│   └── utils.py            # Helper utilities
├── public/
│   └── index.html          # Web app (single-file, no build needed)
├── examples/
│   ├── VulnerableVault.sol  # Example vulnerable contract
│   └── SafeVault.sol        # Example secure contract
├── docs/
│   ├── screenshot.png       # App screenshot
│   └── logo.svg             # ShieldScan logo
├── requirements.txt
├── LICENSE
└── README.md
```

## Example Output

```
╔══════════════════════════════════════════════════════════════╗
║  ShieldScan — Smart Contract Vulnerability Scanner          ║
╚══════════════════════════════════════════════════════════════╝

 Target: VulnerableVault.sol
 Lines:  23 | Patterns: 14 | Time: 0.38s

 ┌─────────────────────────────────────────────────────────┐
 │  FINDINGS: 3 total                                      │
 │  ● Critical: 1  ● High: 1  ● Medium: 1  ○ Low: 0      │
 └─────────────────────────────────────────────────────────┘

 [CRITICAL] Reentrancy Vulnerability (SWC-107)
   Line 11-12 | msg.sender.call{value} before state update
   Fix: Apply Checks-Effects-Interactions pattern

 [HIGH] tx.origin Authentication (SWC-115)
   Line 16 | tx.origin used for authorization
   Fix: Replace with msg.sender

 [MEDIUM] Missing Event Emission (SWC-135)
   Line 21 | State change without event
   Fix: Emit Deposit event after balance update
```

## Use Cases

- **Pre-deployment audit** — Quick first-pass security scan before mainnet deployment
- **Learning tool** — Understand common smart contract vulnerabilities with real examples
- **CI/CD integration** — Automate security checks in your development pipeline
- **Bug bounty recon** — Rapid assessment of target contracts on Immunefi, Code4rena, etc.

## Limitations

ShieldScan is a **static pattern-matching** scanner. It is not a replacement for:

- Professional manual audits
- Symbolic execution tools (Mythril, Manticore)
- Fuzzing tools (Echidna, Foundry)
- Formal verification

Use ShieldScan as a **first line of defense**, then combine with professional tools for production contracts.

## Contributing

Contributions are welcome! You can help by:

1. Adding new vulnerability patterns
2. Improving detection accuracy
3. Submitting false positive reports
4. Improving documentation

## License

MIT License — free to use, modify, and distribute.

## Acknowledgments

- [SWC Registry](https://swcregistry.io) — Smart Contract Weakness Classification
- [OpenZeppelin](https://openzeppelin.com) — Security best practices
- [Trail of Bits](https://www.trailofbits.com) — Slither & security research
- [The Covenant of Humanistic Technologies](https://manifest.human.tech) — Universal Security principle

---

<p align="center">
  <strong>Built with 🛡️ for the Web3 community</strong>
  <br/>
  <sub>Security is a public good.</sub>
</p>
