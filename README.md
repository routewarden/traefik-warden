<div align="center">
  <img src="assets/icon.svg" alt="RouteWarden Logo" width="140" height="140" />
  <h1>RouteWarden</h1>
  <p><strong>Lightweight Traefik middleware to block sensitive file exposure (.env, .git, backups), neutralize path-evasion tricks, whitelist trusted IPs, and respond cleanly before requests hit your backend.</strong></p>
</div>

<p align="center">
  <a href="https://github.com/routewarden/traefik-warden/releases"><img src="https://img.shields.io/github/v/release/routewarden/traefik-warden?color=blue" alt="GitHub Release" /></a>
  <a href="https://github.com/routewarden/traefik-warden/actions/workflows/ci.yml"><img src="https://github.com/routewarden/traefik-warden/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI Status" /></a>
  <a href="https://traefik.io"><img src="https://img.shields.io/badge/Traefik-v2.x%20%7C%20v3.x-24A1C1.svg?logo=traefik&logoColor=white" alt="Traefik Compatibility: v2.x | v3.x" /></a>
  <a href="https://pkg.go.dev/github.com/routewarden/traefik-warden"><img src="https://pkg.go.dev/badge/github.com/routewarden/traefik-warden.svg" alt="Go Reference" /></a>
  <a href="https://routewarden.github.io/docs/guide/testing"><img src="https://img.shields.io/badge/Coverage-98.4%25-brightgreen.svg" alt="Test Coverage: 98.4%" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT" /></a>
  <a href="https://routewarden.github.io/docs/"><img src="https://img.shields.io/badge/Docs-VitePress%20Wiki-6366f1.svg" alt="Documentation Site" /></a>
</p>

---

> **Live Playground**: Test rules, response modes, and bypass behaviors directly in your browser: [https://routewarden.github.io/docs/?playground=open](https://routewarden.github.io/docs/?playground=open)  
> **Documentation & Guides**: [https://routewarden.github.io/docs/](https://routewarden.github.io/docs/)  
> **Example Scenarios**: [`examples/`](examples/) (Docker Compose and Kubernetes CRDs)

---

## Supported Traefik Versions

| Traefik Version | Status | Notes |
|---|---|---|
| **Traefik v3.x** (v3.0, v3.1, v3.2+) | Supported | Runs via standard Yaegi runtime, Docker labels, and Kubernetes CRDs |
| **Traefik v2.x** (v2.8 – v2.11+) | Supported | Compatible with Traefik v2 plugin mechanism |
| **Traefik v1.x** | Not Supported | Traefik v1 does not support plugins |

---

## What is RouteWarden?

Web apps accidentally expose sensitive files and administration paths all the time. Automated bots and scanners crawl the internet looking for these files around the clock.

**RouteWarden** sits directly inside Traefik to catch these requests before they ever reach your upstream application. Written in pure Go with zero external dependencies, it adds minimal overhead while giving you fine-grained control over how scanner probes are handled.

### Key Capabilities

- **Block Common Sensitive Files**: Protects `.env*`, `.git`, `.aws`, `.sql`, `.bak`, `.conf`, `.yaml`, server logs, and debug endpoints out of the box.
- **Normalize Sneaky Paths**: Stops common evasion techniques like double URL-encoding (`%252e%252e`), path traversal, matrix parameters (`/;param/.env`), Windows backslashes, and null bytes before evaluating rules.
- **Whitelist Trusted IPs**: Let office networks, VPNs, or internal subnets bypass inspection using single IPs or CIDR blocks (`10.0.0.0/8`, `100.64.0.0/10`).
- **Flexible Response Actions**: Choose how to answer blocked requests. Return a simple **404 Not Found** so attackers think the path doesn't exist, send **403 Forbidden**, render custom JSON or HTML, issue honeypot redirects, require **Cloudflare Turnstile or hCaptcha** challenges, silently drop TCP connections, or trigger an active **gzip bomb** against scanners.

---

## Quick Start (Return 404 on Probes)

Returning a standard `404 Not Found` is often the best choice: attackers cannot distinguish between a protected secret and a path that never existed.

### Option A: Docker Compose

```yaml
services:
  traefik:
    image: traefik:v3.1
    command:
      - "--api.insecure=true"
      - "--providers.docker=true"
      - "--entrypoints.web.address=:80"
      - "--experimental.plugins.routewarden.modulename=github.com/routewarden/traefik-warden"
      - "--experimental.plugins.routewarden.version=v1.1.0"
    ports:
      - "80:80"
    volumes:
      - "/var/run/docker.sock:/var/run/docker.sock:ro"

  webapp:
    image: nginx:alpine
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.webapp.rule=Host(`localhost`)"
      - "traefik.http.routers.webapp.entrypoints=web"
      - "traefik.http.routers.webapp.middlewares=warden-shield"

      # (Default: true) Enable middleware
      - "traefik.http.middlewares.warden-shield.plugin.routewarden.enabled=true"
      # (Default: true) Block common sensitive files (.env*, .git, .aws, .sql, .bak, .log, etc.)
      - "traefik.http.middlewares.warden-shield.plugin.routewarden.enableDefaultPatterns=true"
      # (Default: []) (Optional) Custom regex patterns to block
      - "traefik.http.middlewares.warden-shield.plugin.routewarden.pathPatterns=(?i)^/admin(/.*)?$,(?i)^/api/internal(/.*)?$"
      # (Optional) Exceptions that should always be allowed (Default: [])
      - "traefik.http.middlewares.warden-shield.plugin.routewarden.allowPatterns=(?i)^/api/internal/health$,(?i)^/robots\\.txt$"
      # Return 404 instead of 403 (Default mode: text, Default statusCode: 403)
      - "traefik.http.middlewares.warden-shield.plugin.routewarden.response.mode=text"
      - "traefik.http.middlewares.warden-shield.plugin.routewarden.response.statusCode=404"
      - "traefik.http.middlewares.warden-shield.plugin.routewarden.response.body=404 page not found"
```

---

### Option B: Traefik File Configuration (`dynamic_conf.yml`)

#### 1. Static Configuration (`traefik.yml`)
```yaml
experimental:
  plugins:
    routewarden:
      moduleName: github.com/routewarden/traefik-warden
      version: v1.1.0
```

#### 2. Dynamic Configuration (`dynamic_conf.yml`)
```yaml
http:
  middlewares:
    warden-404:
      plugin:
        routewarden:
          enabled: true
          enableDefaultPatterns: true
          # Block internal or admin endpoints
          pathPatterns:
            - '(?i)^/admin(/.*)?$'
            - '(?i)^/api/internal(/.*)?$'
          # Allow specific public paths or health checks
          allowPatterns:
            - '(?i)^/api/internal/health$'
            - '(?i)^/robots\.txt$'
          # Whitelist internal office / VPN ranges
          allowedIps:
            - "127.0.0.1"
            - "10.0.0.0/8"
          # Return 404 for blocked requests
          response:
            mode: text
            statusCode: 404
            body: "404 page not found"

  routers:
    app-router:
      rule: "Host(`app.example.com`)"
      entryPoints:
        - web
      middlewares:
        - warden-404
      service: app-service
```

---

## Configuration Reference

| Option | Type | Default | Description |
|---|---|---|---|
| `enabled` | `bool` | `true` | Enables or disables the middleware. |
| `enableDefaultPatterns` | `bool` | `true` | Blocks common sensitive files (`.env*`, `.git`, `.aws`, `.sql`, `.bak`, `.log`, configs). |
| `enableDefaultAllowPatterns` | `bool` | `true` | Keeps standard crawler and discovery files accessible (`/robots.txt`, `/sitemap.xml`, `/.well-known/*`). |
| `pathPatterns` | `[]string` | `[]` | Additional custom regular expressions to block. |
| `allowPatterns` | `[]string` | `[]` | Regular expressions for paths that should always bypass blocking. |
| `allowedIps` | `[]string` | `[]` | Trusted IPv4/IPv6 addresses or CIDR blocks allowed to bypass path inspection. |
| `methods` | `[]string` | `["GET"]` | HTTP request methods to inspect (for example: `["GET", "POST"]`). Other methods pass through. |
| `checkQuery` | `bool` | `false` | When true, also inspects query parameters against blocked patterns. |
| `debug` | `bool` | `false` | When true, enables verbose debug logging to standard output. |
| `securityLog` | `bool` | `true` | When true, emits structured JSON security audit logs on block (CrowdSec / SIEM compatible). |
| `response.mode` | `string` | `"text"` | Action to take when a request is blocked: `"text"`, `"json"`, `"html"`, `"xml"`, `"captcha"`, `"redirect"`, `"proxy"`, `"silentDrop"`, `"gzipBomb"`, `"tarpit"`, `"fakeSuccess"`, `"rateLimitChallenge"`, or `"infiniteStream"`. |
| `response.statusCode` | `int` | `403` | HTTP status code returned to the client (such as `404`, `403`, `401`, or `429`). |
| `response.body` | `string` | `""` | Custom payload returned in the response body. |

> For the complete list of settings (including Captcha keys, custom HTML templates, and header injection), read the **[Full Configuration Reference](https://routewarden.github.io/docs/reference/configuration)**.  
> **Note on `gzipBomb`**: Use this mode only on verified honeypot paths or endpoints targeted exclusively by bots (such as `/.env` or `/wp-login.php`). Never use it on shared generic routes where normal users or legitimate crawlers might get caught. Always keep `enableDefaultAllowPatterns: true` to avoid blocking `/robots.txt`.

---

## CLI & Config Generation

You can use the official [`rwarden`](https://routewarden.github.io/cli/) CLI tool to test path rules offline, validate configurations, and automatically generate Traefik dynamic YAML or Docker Compose labels directly from a unified `routewarden.json` schema:

```bash
# Install RouteWarden CLI
curl -fsSL https://routewarden.github.io/cli/install.sh | bash

# Or run via Docker
docker run --rm ghcr.io/routewarden/cli:latest version
```

### Generating Traefik Configurations:

```bash
# Generate Traefik dynamic YAML middleware definition (dynamic.yml)
rwarden generate --target traefik --config routewarden.json > dynamic.yml

# Generate Docker Compose labels block
rwarden generate --target traefik-labels --config routewarden.json

# Test a suspicious probe path against rules offline
rwarden test --path "/.env"
```

For complete documentation on the CLI, installation methods, and options, visit the **[RouteWarden CLI Documentation](https://routewarden.github.io/cli/)**.

---

## Documentation & Guides

For detailed setup instructions, architecture deep dives, and production examples, check the documentation:

- [Interactive Live Playground](https://routewarden.github.io/docs/?playground=open)
- [Getting Started & Installation](https://routewarden.github.io/docs/guide/getting-started)
- [Architecture & Request Pipeline](https://routewarden.github.io/docs/guide/architecture)
- [Local Development & Testing](https://routewarden.github.io/docs/guide/local-deployment)
- [Testing Architecture & Coverage](https://routewarden.github.io/docs/guide/testing)
- [Configuration Reference](https://routewarden.github.io/docs/reference/configuration)
- [Response Modes & Defense Actions](https://routewarden.github.io/docs/reference/response-modes)
- [Custom Path Patterns & Regex](https://routewarden.github.io/docs/reference/custom-paths)
- [Anti-Evasion Engine](https://routewarden.github.io/docs/reference/anti-evasion)
- [CrowdSec Integration & Auto-Ban](https://routewarden.github.io/docs/examples/crowdsec)
- [Global EntryPoint Shield Recipe](https://routewarden.github.io/docs/examples/docker-compose-global)
- [IP & CIDR Whitelisting](https://routewarden.github.io/docs/examples/ip-whitelisting)
- [Cloudflare Turnstile & hCaptcha](https://routewarden.github.io/docs/examples/captcha)
- [Kubernetes IngressRoute CRD](https://routewarden.github.io/docs/examples/kubernetes)

---

## Testing & Quality

RouteWarden is tested against automated data races and maintains **98.4% statement test coverage**:

| Test Suite | Scope | Command | CI Status |
|---|---|---|---|
| **Go Unit & Race Tests** | Core engine, IP CIDR filter, path normalization, response modes, and evasion vectors | `go test -v -race ./...` | [![CI](https://github.com/routewarden/traefik-warden/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/routewarden/traefik-warden/actions/workflows/ci.yml) |
| **Statement Coverage** | Full test coverage report across all packages (98.4%) | `go test -coverprofile=coverage.out ./...` | 98.4% Coverage |

```bash
# Run tests with the Go race detector
go test -v -race ./...

# Generate coverage profile
go test -coverprofile=coverage.out ./... && go tool cover -func=coverage.out
```

## License

This project is licensed under the [MIT License](LICENSE).
