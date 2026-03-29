# SCG Deployment

Static file server for `scg.bds421.com` — serves install script, release binaries, and landing page.

## Architecture

```
Internet → Traefik (HTTPS + Let's Encrypt) → nginx (static files)
```

- **Traefik v2.11**: TLS termination, automatic cert renewal, HTTP→HTTPS redirect
- **nginx:alpine**: Serves install.sh, release binaries, landing page

## Server

```
Host: 138.201.254.15
Path: /root/bds421/2026/scg/
DNS:  scg.bds421.com → 138.201.254.15
```

## Directory Layout (on server)

```
/root/bds421/2026/scg/
├── docker-compose.yml
├── nginx.conf
├── install.sh
├── traefik/letsencrypt/    # auto-managed by Traefik
└── releases/
    ├── latest/
    │   ├── version          # "v0.1.14"
    │   ├── scg-linux-amd64
    │   ├── scg-linux-arm64
    │   ├── scg-darwin-amd64
    │   ├── scg-darwin-arm64
    │   └── checksums.txt
    └── v0.1.14/
        └── (same files)
```

## Deploy

```bash
# Start/restart
ssh root@138.201.254.15 "cd /root/bds421/2026/scg && docker compose up -d"

# View logs
ssh root@138.201.254.15 "docker logs scg-traefik"
ssh root@138.201.254.15 "docker logs scg-web"

# Stop
ssh root@138.201.254.15 "cd /root/bds421/2026/scg && docker compose down"
```

## Release a New Version

```bash
# 1. Cross-compile
VERSION=v0.1.15
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=$VERSION" -o /tmp/scg-linux-amd64 ./cmd/scg/
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=$VERSION" -o /tmp/scg-linux-arm64 ./cmd/scg/
GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=$VERSION" -o /tmp/scg-darwin-amd64 ./cmd/scg/
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=$VERSION" -o /tmp/scg-darwin-arm64 ./cmd/scg/

# 2. Checksums
cd /tmp && shasum -a 256 scg-linux-amd64 scg-linux-arm64 scg-darwin-amd64 scg-darwin-arm64 > checksums.txt

# 3. Upload
ssh root@138.201.254.15 "mkdir -p /root/bds421/2026/scg/releases/$VERSION"
scp /tmp/scg-linux-* /tmp/scg-darwin-* /tmp/checksums.txt root@138.201.254.15:/root/bds421/2026/scg/releases/$VERSION/

# 4. Update latest
ssh root@138.201.254.15 "cp /root/bds421/2026/scg/releases/$VERSION/* /root/bds421/2026/scg/releases/latest/ && echo '$VERSION' > /root/bds421/2026/scg/releases/latest/version"

# 5. Verify
curl -sSL https://scg.bds421.com/releases/latest/version
```

## Endpoints

| URL | Content |
|---|---|
| `https://scg.bds421.com/` | Landing page |
| `https://scg.bds421.com/health` | Health check (`ok`) |
| `https://scg.bds421.com/install.sh` | Install script |
| `https://scg.bds421.com/releases/` | Directory listing |
| `https://scg.bds421.com/releases/latest/version` | Current version string |
| `https://scg.bds421.com/releases/latest/scg-{os}-{arch}` | Binary |
| `https://scg.bds421.com/releases/latest/checksums.txt` | SHA256 checksums |
