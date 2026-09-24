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
}

// NewIPFilter parses and creates an IPFilter from a list of IP strings and CIDR notation subnets.
func NewIPFilter(allowedIPs []string) (*IPFilter, error) {
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

	return &IPFilter{
		allowedIPs:  ips,
		allowedNets: nets,
	}, nil
}

// IsAllowed returns true if the client IP in the request matches any whitelisted IP or subnet.
func (f *IPFilter) IsAllowed(req *http.Request) bool {
	if len(f.allowedIPs) == 0 && len(f.allowedNets) == 0 {
		return false
	}

	clientIPStr := ExtractClientIP(req)
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

// ExtractClientIP extracts the client IP address from proxy headers or RemoteAddr socket.
func ExtractClientIP(req *http.Request) string {
	// Check X-Forwarded-For header first (first IP is the originating client)
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			ip := strings.TrimSpace(parts[0])
			if ip != "" {
				return cleanIP(ip)
			}
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
