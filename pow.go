package traefik_warden

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultPoWDifficulty represents the standard number of leading zero bits required (16 bits ~= 65,536 iterations, ~25ms in JS).
	DefaultPoWDifficulty = 16
	// DefaultPoWTimeoutSeconds is the challenge lifetime in seconds (5 minutes).
	DefaultPoWTimeoutSeconds = 300
	// DefaultPoWSecret is the fallback secret used to sign PoW challenges if none is provided.
	DefaultPoWSecret = "routewarden-pow-challenge-seed-secret"
)

// leadingZeros8 returns the count of leading zero bits in a byte (0..8).
func leadingZeros8(b byte) int {
	if b >= 128 {
		return 0
	}
	if b >= 64 {
		return 1
	}
	if b >= 32 {
		return 2
	}
	if b >= 16 {
		return 3
	}
	if b >= 8 {
		return 4
	}
	if b >= 4 {
		return 5
	}
	if b >= 2 {
		return 6
	}
	if b >= 1 {
		return 7
	}
	return 8
}

// CountLeadingZeroBits returns the total number of consecutive leading zero bits in a slice.
func CountLeadingZeroBits(data []byte) int {
	zeros := 0
	for _, b := range data {
		if b == 0 {
			zeros += 8
		} else {
			zeros += leadingZeros8(b)
			break
		}
	}
	return zeros
}

// NormalizePoWIP strips port and zone identifier from IP string for consistent binding.
func NormalizePoWIP(ip string) string {
	ip = strings.TrimSpace(ip)
	if host, _, err := net.SplitHostPort(ip); err == nil {
		ip = host
	}
	ip = strings.Trim(ip, "[]")
	if idx := strings.IndexByte(ip, '%'); idx != -1 {
		ip = ip[:idx]
	}
	return ip
}

// GeneratePoWChallenge creates a signed challenge token for clientIP.
// Token format: <timestamp>.<difficulty>.<salt>.<signature>
func GeneratePoWChallenge(clientIP, secret string, difficulty int, now time.Time) (string, error) {
	if difficulty <= 0 {
		difficulty = DefaultPoWDifficulty
	}
	if secret == "" {
		secret = DefaultPoWSecret
	}
	normIP := NormalizePoWIP(clientIP)

	saltBytes := make([]byte, 8)
	if _, err := rand.Read(saltBytes); err != nil {
		return "", fmt.Errorf("failed to generate random salt: %w", err)
	}
	salt := hex.EncodeToString(saltBytes)

	timestamp := strconv.FormatInt(now.Unix(), 10)
	diffStr := strconv.Itoa(difficulty)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(normIP + ":" + timestamp + ":" + diffStr + ":" + salt))
	sig := hex.EncodeToString(mac.Sum(nil))

	return timestamp + "." + diffStr + "." + salt + "." + sig, nil
}

// VerifyPoWSolution verifies a solved challenge submitted by clientIP.
// Solution format: <timestamp>.<difficulty>.<salt>.<signature>.<nonce>
func VerifyPoWSolution(clientIP, secret, solution string, timeoutSeconds int, now time.Time) (bool, string) {
	if timeoutSeconds <= 0 {
		timeoutSeconds = DefaultPoWTimeoutSeconds
	}
	if secret == "" {
		secret = DefaultPoWSecret
	}
	normIP := NormalizePoWIP(clientIP)

	parts := strings.Split(strings.TrimSpace(solution), ".")
	if len(parts) != 5 {
		return false, "invalid_pow_format"
	}

	tsStr, diffStr, salt, sig, nonceStr := parts[0], parts[1], parts[2], parts[3], parts[4]

	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return false, "invalid_pow_timestamp"
	}

	diff, err := strconv.Atoi(diffStr)
	if err != nil || diff <= 0 || diff > 64 {
		return false, "invalid_pow_difficulty"
	}

	if _, err := strconv.ParseUint(nonceStr, 10, 64); err != nil {
		return false, "invalid_pow_nonce"
	}

	// 1. Time expiration check
	elapsed := now.Unix() - ts
	if elapsed < -10 || elapsed > int64(timeoutSeconds) {
		return false, "expired_pow"
	}

	// 2. HMAC signature verification
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(normIP + ":" + tsStr + ":" + diffStr + ":" + salt))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(sig), []byte(expectedSig)) {
		return false, "invalid_pow_signature"
	}

	// 3. Hashcash computation check: SHA-256(challenge + ":" + nonce) has >= difficulty leading zero bits
	challenge := tsStr + "." + diffStr + "." + salt + "." + sig
	payload := challenge + ":" + nonceStr
	h := sha256.Sum256([]byte(payload))
	zeros := CountLeadingZeroBits(h[:])

	if zeros < diff {
		return false, "insufficient_pow_work"
	}

	return true, ""
}

// SolvePoW finds the nonce that satisfies challenge for test and verification purposes.
func SolvePoW(challenge string, difficulty int) uint64 {
	var nonce uint64
	for {
		payload := challenge + ":" + strconv.FormatUint(nonce, 10)
		h := sha256.Sum256([]byte(payload))
		if CountLeadingZeroBits(h[:]) >= difficulty {
			return nonce
		}
		nonce++
	}
}

// extractPoWToken extracts the PoW solution token from request headers or cookies.
func extractPoWToken(req *http.Request) string {
	if req == nil {
		return ""
	}
	if tok := strings.TrimSpace(req.Header.Get("X-RW-PoW")); tok != "" {
		return tok
	}
	if cookie, err := req.Cookie("__rw_pow"); err == nil && strings.TrimSpace(cookie.Value) != "" {
		return strings.TrimSpace(cookie.Value)
	}
	return ""
}

// GeneratePoWHTML returns the self-contained, responsive challenge page with inline Web Worker solver.
func GeneratePoWHTML(challenge string, difficulty, timeoutSeconds int) string {
	if timeoutSeconds <= 0 {
		timeoutSeconds = DefaultPoWTimeoutSeconds
	}
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Verification &middot; RouteWarden</title>
  <style>
    :root {
      --bg: #090d16;
      --card-bg: rgba(17, 24, 39, 0.85);
      --border: rgba(55, 65, 81, 0.6);
      --text: #f3f4f6;
      --text-muted: #9ca3af;
      --accent: #3b82f6;
      --accent-glow: rgba(59, 130, 246, 0.35);
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      padding: 1.5rem;
    }
    .card {
      background: var(--card-bg);
      backdrop-filter: blur(12px);
      border: 1px solid var(--border);
      border-radius: 1rem;
      padding: 2.25rem;
      max-width: 440px;
      width: 100%%;
      text-align: center;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
    }
    .icon {
      width: 52px;
      height: 52px;
      margin: 0 auto 1.25rem;
      color: var(--accent);
      display: flex;
      align-items: center;
      justify-content: center;
      border-radius: 50%%;
      background: var(--accent-glow);
    }
    .icon svg {
      width: 28px;
      height: 28px;
      animation: spin 3s linear infinite;
    }
    @keyframes spin {
      100%% { transform: rotate(360deg); }
    }
    h1 {
      font-size: 1.35rem;
      font-weight: 600;
      margin-bottom: 0.5rem;
    }
    p {
      color: var(--text-muted);
      font-size: 0.9rem;
      line-height: 1.5;
      margin-bottom: 1.5rem;
    }
    .progress-bar {
      width: 100%%;
      height: 6px;
      background: rgba(55, 65, 81, 0.8);
      border-radius: 9999px;
      overflow: hidden;
      margin-bottom: 1rem;
      position: relative;
    }
    .progress-fill {
      height: 100%%;
      width: 30%%;
      background: linear-gradient(90deg, #3b82f6, #60a5fa);
      border-radius: 9999px;
      animation: indeterminate 1.5s infinite ease-in-out;
    }
    @keyframes indeterminate {
      0%% { transform: translateX(-100%%); width: 30%%; }
      50%% { width: 60%%; }
      100%% { transform: translateX(350%%); width: 30%%; }
    }
    .status {
      font-size: 0.8rem;
      color: var(--text-muted);
      font-mono: monospace;
    }
    .footer {
      margin-top: 1.5rem;
      font-size: 0.75rem;
      color: #6b7280;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">
      <svg fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
      </svg>
    </div>
    <h1>Checking your browser</h1>
    <p>Please wait a moment while we verify your connection security before proceeding.</p>
    <div class="progress-bar">
      <div class="progress-fill"></div>
    </div>
    <div id="status" class="status">Solving cryptographic challenge...</div>
    <div class="footer">Protected by RouteWarden &middot; Proof-of-Work Verification</div>
  </div>

  <script>
    (function() {
      const challenge = %q;
      const difficulty = %d;
      const timeout = %d;

      function countLeadingZeroBits(buf) {
        const bytes = new Uint8Array(buf);
        let zeros = 0;
        for (let i = 0; i < bytes.length; i++) {
          const b = bytes[i];
          if (b === 0) {
            zeros += 8;
          } else {
            let z = 0;
            if (b >= 128) z = 0;
            else if (b >= 64) z = 1;
            else if (b >= 32) z = 2;
            else if (b >= 16) z = 3;
            else if (b >= 8) z = 4;
            else if (b >= 4) z = 5;
            else if (b >= 2) z = 6;
            else if (b >= 1) z = 7;
            else z = 8;
            zeros += z;
            break;
          }
        }
        return zeros;
      }

      async function solve() {
        const encoder = new TextEncoder();
        let nonce = 0;
        const batchSize = 2500;

        while (true) {
          const promises = [];
          for (let i = 0; i < batchSize; i++) {
            const currentNonce = nonce + i;
            const payload = challenge + ":" + currentNonce;
            const data = encoder.encode(payload);
            promises.push(
              crypto.subtle.digest("SHA-256", data).then(hash => ({
                nonce: currentNonce,
                zeros: countLeadingZeroBits(hash)
              }))
            );
          }

          const results = await Promise.all(promises);
          for (let res of results) {
            if (res.zeros >= difficulty) {
              const solution = challenge + "." + res.nonce;
              document.cookie = "__rw_pow=" + solution + "; Path=/; SameSite=Lax; Max-Age=" + timeout;
              document.getElementById("status").innerText = "Verification complete! Redirecting...";
              window.location.reload();
              return;
            }
          }
          nonce += batchSize;
          await new Promise(r => setTimeout(r, 0));
        }
      }

      if (window.crypto && window.crypto.subtle) {
        solve().catch(function(err) {
          document.getElementById("status").innerText = "Verification error. Please refresh.";
        });
      } else {
        document.getElementById("status").innerText = "Browser does not support Web Crypto. Please upgrade.";
      }
    })();
  </script>
</body>
</html>`, challenge, difficulty, timeoutSeconds)
}

