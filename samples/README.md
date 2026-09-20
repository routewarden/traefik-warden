# RouteWarden Samples & Live Testing Environment (Traefik v3)

This directory provides a multi-port Docker Compose environment and an automated test suite (`test.sh`) to verify all RouteWarden response modes, security flags, path-evasion protections, and IP filtering capabilities in Traefik.

## Architecture

The test environment provisions:
1. **Traefik Container**: Loads RouteWarden via `localPlugins` directly from source code and exposes 14 dedicated test ports mapped in `samples/dynamic.yml` and `samples/docker-compose.yml`.
2. **Honeypot Backend Container**: A lightweight Python HTTP server on port `9999` to verify `mode proxy` (transparent honeypot redirection).
3. **Echo Backend Container**: A lightweight Python HTTP server on port `8888` simulating protected upstream microservices.

---

## Directory Layout

```
samples/
├── dynamic.yml          # Multi-port dynamic router & middleware configuration
├── docker-compose.yml   # Multi-container orchestration (Traefik + Honeypot + Echo backend)
├── test.sh              # Bash verification script testing each port and scenario
└── README.md            # Documentation and instructions
```

---

## Port Mappings & Features Tested

| Port | Mode / Feature | Verification Scenario |
| :--- | :--- | :--- |
| **8080** | Core & JSON | Built-in `.env`, `.git`, SQL dumps, actuator endpoints; anti-evasion traversal (`%252e%252e`), matrix parameters (`/;param`); `check_query`; IP allowlist bypass via `allowed_ips`; `allow_patterns` overrides. |
| **8081** | `html` | Returns custom HTML error page with `text/html` headers. |
| **8082** | `text` | Returns plain text message with `text/plain` headers. |
| **8083** | `xml` | Returns structured `<Error>` XML document. |
| **8084** | `captcha` | Serves security challenge page with Cloudflare Turnstile markup. |
| **8085** | `redirect` | Emits HTTP 302 redirect with `Location` header to honeypot sinkhole. |
| **8086** | `rateLimitChallenge` | Emits HTTP 429 status code with `Retry-After: 180` header. |
| **8087** | `fakeSuccess` | Returns synthetic decoy credentials (`.env`, git HEAD, actuator). |
| **8088** | `gzipBomb` | Emits compressed gzip stream with `Content-Encoding: gzip`. |
| **8089** | `silentDrop` | Abruptly terminates TCP socket connection upon probe. |
| **8090** | `infiniteStream` | Streams continuous garbage data chunks to exhaust automated parsers. |
| **8091** | `proxy` | Transparently reverse-proxies blocked probes to honeypot backend container. |
| **8092** | `disable` | Flag verification: RouteWarden disabled, all requests pass through to upstream. |
| **8093** | `methods` | Verb filter verification: Only inspects `POST` & `DELETE`; `GET` bypasses filter. |

---

## Running the Live Tests

### 1. Start the Environment

From the repository root or samples directory:

```bash
cd samples
docker compose up -d
```

### 2. Execute the Test Suite

```bash
./test.sh
```

### 3. Teardown

```bash
docker compose down -v
```
