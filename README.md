# Panopticon

**AI-native HTTPS Control &amp; Analysis Proxy**

Panopticon は全 HTTPS 通信を制御・可視化する汎用 MITM プロキシ。Little Snitch の「許可制御」と mitmproxy の「トラフィック解析」を統合し、AI agent が MCP 経由でプログラム可能なレイヤーを提供する。

## Features

- **MITM HTTPS インターセプト**: CA 証明書を自動生成し、すべての HTTPS 通信を透過的に復号
- **ルールベース制御**: host/path/method/process 単位の allow/deny/log/mask ルール
- **トラフィックキャプチャ**: SQLite + JSONL でリクエスト/レスポンスを永続保存
- **macOS プロセス検出**: プロセス ID→bundle_id でアプリケーション単位の制御
- **MCP インターフェース**: AI agent からルール定義・トラフィック照会・統計取得
- **プラグインシステム**: Go plugin .so による拡張（Phase 6）

## Quick Start

```bash
# Build
make build

# Generate CA cert and start proxy
./panopticon

# In another terminal, install the CA cert (one-time)
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain \
  ~/.local/share/panopticon/panopticon-ca.pem

# Test with curl
curl -x http://localhost:8080 https://example.com
```

## Configuration

Config file: `~/.config/panopticon/panopticon.yaml`

```yaml
listen: ":8080"
verbose: false
rules:
  - name: "allow-claude-code"
    priority: 200
    conditions:
      - type: process
        value: "Q6L2SF6YDW.com.anthropic.claude-code"
    action:
      action: allow
```

## Architecture

```
Client → goproxy MITM → Rule Engine → Plugin Hooks → Capture Store → Upstream
                          ↓
                     MCP Server (stdio)
                     Prometheus Metrics
```

## Phases

| Phase | Feature | Status |
|-------|---------|--------|
| P1 | Core MITM Proxy + CA | ✅ Complete |
| P2 | Rule Engine | 🔲 |
| P3 | Traffic Capture | 🔲 |
| P4 | macOS Process Detection | 🔲 |
| P5 | MCP Server | 🔲 |
| P6 | Plugin System | 🔲 |
| P7 | Observability | 🔲 |
| P8 | Silent-failure Defense | 🔲 |

## License

MIT
