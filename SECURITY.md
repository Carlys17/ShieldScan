# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| main    | :white_check_mark: |

## Reporting a Vulnerability

Please report security vulnerabilities to the repository owner via GitHub Issues.

## Security Considerations

This tool analyzes smart contracts for vulnerabilities. When using:

1. **Never** submit private keys or mnemonics
2. **Never** analyze contracts on production networks with real funds
3. Always verify findings with manual review
4. Use isolated environment for scanning unknown contracts

## Code Security

- Input validation on all contract addresses
- No arbitrary code execution
- Sandboxed analysis environment
