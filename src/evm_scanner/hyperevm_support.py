"""HyperEVM chain support for ShieldScan."""

HYPEREVM_CONFIG = {
    "chain_id": 999,
    "name": "HyperEVM",
    "rpc_urls": ["https://rpc.hyperliquid.xyz/evm"],
    "explorer": "https://hyperevmscan.io",
    "explorer_api": "https://api.hyperevmscan.io/api",
    "native_currency": {"name": "HYPE", "symbol": "HYPE", "decimals": 18},
}

def get_explorer_url(address: str, tx_hash: str = None) -> str:
    base = HYPEREVM_CONFIG["explorer"]
    return f"{base}/tx/{tx_hash}" if tx_hash else f"{base}/address/{address}"

def is_supported_chain(chain_id: int) -> bool:
    return chain_id == HYPEREVM_CONFIG["chain_id"]
