package traefik_warden

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"time"
)

// DefaultRobotsHoneypotSecret is the fallback secret used when no custom secret is provided.
const DefaultRobotsHoneypotSecret = "routewarden-default-robots-trap-seed"

// GetRobotsHoneypotToken generates a deterministic 12-hex-character token for a given date.
func GetRobotsHoneypotToken(secret string, t time.Time) string {
	if strings.TrimSpace(secret) == "" {
		secret = DefaultRobotsHoneypotSecret
	}
	dateStr := t.UTC().Format("2006-01-02")
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(dateStr))
	fullHex := hex.EncodeToString(mac.Sum(nil))
	if len(fullHex) >= 12 {
		return fullHex[:12]
	}
	return fullHex
}

// GetActiveRobotsHoneypotTraps returns the current day's trap path for injection (e.g. "/_rw_trap_f8a3e9c1/")
// and the list of active trap prefixes (today and yesterday) to accept across UTC day rollovers.
func GetActiveRobotsHoneypotTraps(secret string, now time.Time) (activeTrapPath string, validPrefixes []string) {
	todayToken := GetRobotsHoneypotToken(secret, now)
	yesterdayToken := GetRobotsHoneypotToken(secret, now.Add(-24*time.Hour))

	activeTrapPath = "/_rw_trap_" + todayToken + "/"
	validPrefixes = []string{
		"/_rw_trap_" + todayToken,
		"/_rw_trap_" + yesterdayToken,
	}
	return activeTrapPath, validPrefixes
}

// IsRobotsTxtPath checks whether a given request path targets /robots.txt.
func IsRobotsTxtPath(p string) bool {
	clean := strings.ToLower(strings.TrimSpace(p))
	clean = strings.TrimRight(clean, "/")
	return clean == "/robots.txt"
}

// InjectRobotsTxtTrap appends the dynamic Disallow honeypot trap to an existing robots.txt content.
func InjectRobotsTxtTrap(body []byte, activeTrapPath string) []byte {
	content := string(body)
	var sb strings.Builder
	sb.WriteString(content)
	if len(content) > 0 && !strings.HasSuffix(content, "\n") {
		sb.WriteString("\n")
	}
	sb.WriteString("\n# RouteWarden Dynamic Honeypot Trap\n")
	sb.WriteString("User-agent: *\n")
	sb.WriteString("Disallow: ")
	sb.WriteString(activeTrapPath)
	sb.WriteString("\n")
	return []byte(sb.String())
}

type robotsResponseBuffer struct {
	http.ResponseWriter
	buf         bytes.Buffer
	statusCode  int
	wroteHeader bool
	header      http.Header
}

func (b *robotsResponseBuffer) Header() http.Header {
	if b.header == nil {
		b.header = make(http.Header)
	}
	return b.header
}

func (b *robotsResponseBuffer) WriteHeader(code int) {
	if !b.wroteHeader {
		b.statusCode = code
		b.wroteHeader = true
	}
}

func (b *robotsResponseBuffer) Write(p []byte) (int, error) {
	if !b.wroteHeader {
		b.WriteHeader(http.StatusOK)
	}
	return b.buf.Write(p)
}

func (b *robotsResponseBuffer) flushOriginal() {
	for k, vv := range b.header {
		for _, v := range vv {
			b.ResponseWriter.Header().Add(k, v)
		}
	}
	b.ResponseWriter.WriteHeader(b.statusCode)
	b.ResponseWriter.Write(b.buf.Bytes())
}
