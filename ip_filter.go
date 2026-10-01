package traefik_warden

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// IPFilter evaluates incoming requests against an IP or CIDR subnet whitelist.
type IPFilter struct {
	allowedIPs  []net.IP
	allowedNets []*net.IPNet
	// trustedNets is the set of upstream proxies (e.g. Traefik, load-balancers) whose
	// X-Forwarded-For / X-Real-IP headers are trusted. When nil/empty, XFF is trusted
	// unconditionally (legacy behaviour). When non-empty, XFF is only honoured if the
	// request's RemoteAddr is a member of this set; otherwise RemoteAddr is used directly,
	// preventing IP-whitelist bypass via forged X-Forwarded-For headers.
	trustedNets []*net.IPNet
}

// NewIPFilter parses and creates an IPFilter from a list of IP strings and CIDR notation subnets.
// trustedProxies is an optional list of IPs/CIDRs whose X-Forwarded-For / X-Real-IP headers
// are considered trustworthy. Pass nil or an empty slice to retain legacy (always-trust-XFF) behaviour.
func NewIPFilter(allowedIPs []string, trustedProxies []string) (*IPFilter, error) {
	var ips []net.IP
	var nets []*net.IPNet

	for _, ipStr := range allowedIPs {
		ipStr = strings.TrimSpace(ipStr)
		if ipStr == "" {
			continue
		}
		if strings.Contains(ipStr, "/") {
			_, ipNet, err := net.ParseCIDR(ipStr)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR subnet %q: %w", ipStr, err)
			}
			nets = append(nets, ipNet)
		} else {
			ip := net.ParseIP(ipStr)
			if ip == nil {
				return nil, fmt.Errorf("invalid IP address %q", ipStr)
			}
			ips = append(ips, ip)
		}
	}

	var trustedNets []*net.IPNet
	for _, proxyStr := range trustedProxies {
		proxyStr = strings.TrimSpace(proxyStr)
		if proxyStr == "" {
			continue
		}
		if strings.Contains(proxyStr, "/") {
			_, ipNet, err := net.ParseCIDR(proxyStr)
			if err != nil {
				return nil, fmt.Errorf("invalid trusted proxy CIDR %q: %w", proxyStr, err)
			}
			trustedNets = append(trustedNets, ipNet)
		} else {
			ip := net.ParseIP(proxyStr)
			if ip == nil {
				return nil, fmt.Errorf("invalid trusted proxy IP %q", proxyStr)
			}
			// Represent a single IP as a host-route net for uniform Contains() handling.
			bits := 128
			if ip.To4() != nil {
				bits = 32
			}
			mask := net.CIDRMask(bits, bits)
			trustedNets = append(trustedNets, &net.IPNet{IP: ip.Mask(mask), Mask: mask})
		}
	}

	return &IPFilter{
		allowedIPs:  ips,
		allowedNets: nets,
		trustedNets: trustedNets,
	}, nil
}

// IsAllowed returns true if the client IP in the request matches any whitelisted IP or subnet.
func (f *IPFilter) IsAllowed(req *http.Request) bool {
	if len(f.allowedIPs) == 0 && len(f.allowedNets) == 0 {
		return false
	}

	clientIPStr := f.extractClientIP(req)
	if clientIPStr == "" {
		return false
	}

	clientIP := net.ParseIP(clientIPStr)
	if clientIP == nil {
		return false
	}

	for _, ip := range f.allowedIPs {
		if ip.Equal(clientIP) {
			return true
		}
	}

	for _, ipNet := range f.allowedNets {
		if ipNet.Contains(clientIP) {
			return true
		}
	}

	return false
}

// extractClientIP resolves the real client IP respecting the trustedNets configuration.
//
// When no trusted proxies are configured, it falls back to the package-level ExtractClientIP
// (legacy XFF-always-trusted behaviour). When trusted proxies are configured, XFF/X-Real-IP
// headers are only honoured if RemoteAddr belongs to a trusted proxy; otherwise RemoteAddr
// is used directly, preventing IP whitelist bypass via forged forwarding headers.
func (f *IPFilter) extractClientIP(req *http.Request) string {
	// Legacy mode: no trusted proxies declared → trust XFF unconditionally.
	if len(f.trustedNets) == 0 {
		return ExtractClientIP(req)
	}

	// Determine the direct peer address (socket-level).
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		host = strings.Trim(strings.TrimSpace(req.RemoteAddr), "[]")
	}
	remoteIP := net.ParseIP(host)

	// Check whether the direct peer is a declared trusted proxy.
	isTrusted := false
	if remoteIP != nil {
		for _, tn := range f.trustedNets {
			if tn.Contains(remoteIP) {
				isTrusted = true
				break
			}
		}
	}

	if isTrusted {
		// The request arrived from a trusted proxy: honour forwarding headers.
		if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			ip := strings.TrimSpace(parts[0])
			if ip != "" {
				return cleanIP(ip)
			}
		}
		if xrip := req.Header.Get("X-Real-IP"); xrip != "" {
			ip := strings.TrimSpace(xrip)
			if ip != "" {
				return cleanIP(ip)
			}
		}
	}

	// Not a trusted proxy (or no usable forwarding header): use the socket address directly.
	if host != "" {
		return strings.Trim(host, "[]")
	}
	return strings.Trim(strings.TrimSpace(req.RemoteAddr), "[]")
}

// ExtractClientIP extracts the client IP address from proxy headers or the RemoteAddr socket.
// This function unconditionally trusts X-Forwarded-For and is intended for logging / diagnostics
// only. For security-critical decisions (IP whitelisting) use IPFilter.extractClientIP instead.
func ExtractClientIP(req *http.Request) string {
	// Check X-Forwarded-For first (left-most entry is the originating client).
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		// Bug 6 fix: strings.Split never returns an empty slice; len(parts)>0 check removed.
		ip := strings.TrimSpace(parts[0])
		if ip != "" {
			return cleanIP(ip)
		}
	}

	// Check X-Real-IP header
	if xrip := req.Header.Get("X-Real-IP"); xrip != "" {
		ip := strings.TrimSpace(xrip)
		if ip != "" {
			return cleanIP(ip)
		}
	}

	// Fallback to RemoteAddr (host:port)
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err == nil && host != "" {
		return strings.Trim(host, "[]")
	}

	return strings.Trim(strings.TrimSpace(req.RemoteAddr), "[]")
}

func cleanIP(raw string) string {
	raw = strings.TrimSpace(raw)
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	}
	return strings.Trim(raw, "[]")
}
