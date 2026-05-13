# HyperEVM Integration Guide

## Overview
ShieldScan now supports HyperEVM chain for smart contract vulnerability scanning.

## Setup
```bash
export HYPEREVM_RPC="https://rpc.hyperliquid.xyz/evm"
export HYPEREVM_EXPLORER_API="https://api.hyperevmscan.io/api"
```

## Scanning
```bash
python -m shieldscan --chain hyperevm --address 0xYourContract
```

## Supported Detectors
- Reentrancy
- Access Control
- Integer Overflow
- Delegatecall Injection
- Unchecked External Calls
- Oracle Manipulation
