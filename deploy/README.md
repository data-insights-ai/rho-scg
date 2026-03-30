# SCG Deployment

Two services on separate subdomains:

```
scg.data-insights.ai       → nginx (landing page, install script, binaries)
api.scg.data-insights.ai   → scgd  (platform API, closed source)
```

## Architecture

```
Internet → Traefik (HTTPS + Let's Encrypt) → nginx (static) | scgd (API)
```

- **Traefik**: TLS termination per subdomain, automatic cert renewal
- **nginx:alpine**: Serves install.sh, release binaries, landing page
- **scgd**: Platform daemon (separate repo)

## Release a New CLI Version

```bash
VERSION=v0.1.27
for pair in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do
  GOOS=${pair%/*} GOARCH=${pair#*/} CGO_ENABLED=0 go build \
    -ldflags "-s -w -X main.version=$VERSION" \
    -o /tmp/scg-${pair%/*}-${pair#*/} ./cmd/scg/
done

cd /tmp && shasum -a 256 scg-linux-* scg-darwin-* > checksums.txt
```

## Endpoints

| URL | Content |
|---|---|
| `https://scg.data-insights.ai/` | Landing page |
| `https://scg.data-insights.ai/health` | Health check (`ok`) |
| `https://scg.data-insights.ai/install.sh` | Install script |
| `https://scg.data-insights.ai/releases/` | Directory listing |
| `https://scg.data-insights.ai/releases/latest/version` | Current version string |
| `https://scg.data-insights.ai/releases/latest/scg-{os}-{arch}` | Binary |
| `https://scg.data-insights.ai/releases/latest/checksums.txt` | SHA256 checksums |
