"""EVM scanner module for multi-chain contract analysis."""

SUPPORTED_CHAINS = {
    "ethereum": {"chain_id": 1, "explorer": "etherscan.io"},
    "arbitrum": {"chain_id": 42161, "explorer": "arbiscan.io"},
    "base": {"chain_id": 8453, "explorer": "basescan.org"},
    "hyperevm": {"chain_id": 999, "explorer": "hyperevmscan.io"},
}
