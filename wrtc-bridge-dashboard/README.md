# wRTC Solana Bridge Dashboard

Real-time monitoring dashboard for the RustChain ↔ Solana wRTC bridge.

## Features

- **Total RTC Locked** — live from RustChain node
- **wRTC Circulating Supply** — from Solana token supply
- **Bridge Health** — status indicators for RustChain, Solana RPC, and Raydium
- **Recent Transactions** — latest wrap/unwrap activity from DexScreener
- **Price Chart** — wRTC price from Raydium DEX
- **Auto-refresh** — updates every 30 seconds

## Tech Stack

- Vanilla HTML/CSS/JS (no build step)
- DexScreener API (free, no auth)
- Solana JSON-RPC
- RustChain node REST API

## Deploy

Simply open `dashboard.html` in a browser, or serve via nginx:

```nginx
location /bridge {
    alias /path/to/wrtc-bridge-dashboard;
    index dashboard.html;
}
```

## Data Sources

| Metric | Source |
|--------|--------|
| RTC Locked | RustChain node `/health` + `/epoch` endpoints |
| wRTC Supply | Solana RPC `getTokenSupply` |
| Price / Txs | DexScreener API |
| Bridge Health | Uptime polling of each endpoint |

## Wallet

C4c7r9WPsnEe6CUfegMU9M7ReHD1pWg8qeSfTBoRcLbg

---

Built for RustChain Bounty #2303.
