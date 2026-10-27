package traefik_warden

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// ASNFilter resolves addresses against an immutable local routing snapshot.
// The JSON database maps ASN identifiers to arrays of IPv4/IPv6 CIDRs.
type ASNFilter struct {
	roots   [2]*asnNode
	allowed map[uint32]bool
}
type asnNode struct {
	children [2]*asnNode
	number   uint32
}

func parseASN(value string) (uint32, error) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(strings.ToUpper(value), "AS") {
		value = value[2:]
	}
	if value == "" {
		return 0, fmt.Errorf("empty ASN")
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid ASN %q", value)
		}
	}
	n, err := strconv.ParseUint(value, 10, 32)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("invalid ASN %q: expected 1..4294967295", value)
	}
	return uint32(n), nil
}

// NewASNFilter validates and loads the database once, outside the request path.
// With no allowed ASNs the feature is disabled and no database is read.
func NewASNFilter(allowed []string, path string) (*ASNFilter, error) {
	f := &ASNFilter{allowed: make(map[uint32]bool)}
	if len(allowed) == 0 {
		return f, nil
	}
	for _, value := range allowed {
		n, err := parseASN(value)
		if err != nil {
			return nil, err
		}
		f.allowed[n] = true
	}
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("asnDB/asn_db is required with allowed ASNs")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("ASN database: %w", err)
	}
	var database map[string][]string
	if err := json.Unmarshal(data, &database); err != nil {
		return nil, fmt.Errorf("ASN database: %w", err)
	}
	seen := make(map[string]uint32)
	found := make(map[uint32]bool)
	for key, prefixes := range database {
		n, err := parseASN(key)
		if err != nil {
			return nil, err
		}
		for _, prefix := range prefixes {
			_, network, err := net.ParseCIDR(prefix)
			if err != nil {
				return nil, fmt.Errorf("ASN %s: invalid prefix %q: %w", key, prefix, err)
			}
			canonical := network.String()
			if previous, ok := seen[canonical]; ok {
				if previous != n {
					return nil, fmt.Errorf("ASN database: conflicting origins for %s", canonical)
				}
				continue
			}
			seen[canonical] = n
			bits, _ := network.Mask.Size()
			f.insert(network, bits, n)
			found[n] = true
		}
	}
	for n := range f.allowed {
		if !found[n] {
			return nil, fmt.Errorf("ASN %d has no prefixes in database", n)
		}
	}

	return f, nil
}

// insert builds separate IPv4 and IPv6 tries. Lookup cost is bounded by address
// width rather than the number of prefixes in a full routing database.
func (f *ASNFilter) insert(network *net.IPNet, bits int, number uint32) {
	family := 1
	ip := network.IP.To16()
	if v4 := network.IP.To4(); v4 != nil {
		family = 0
		ip = v4
		if len(network.Mask) == net.IPv6len {
			bits -= 96
		}
	}
	if f.roots[family] == nil {
		f.roots[family] = &asnNode{}
	}
	node := f.roots[family]
	for i := 0; i < bits; i++ {
		bit := (ip[i/8] >> uint(7-i%8)) & 1
		if node.children[bit] == nil {
			node.children[bit] = &asnNode{}
		}
		node = node.children[bit]
	}
	node.number = number
}

// Lookup returns the origin ASN of the longest matching route, or zero if unknown.
func (f *ASNFilter) Lookup(address string) uint32 {
	if f == nil {
		return 0
	}
	if host, _, err := net.SplitHostPort(address); err == nil {
		address = host
	}
	ip := net.ParseIP(strings.Trim(address, "[]"))
	if ip == nil {
		return 0
	}
	family := 1
	if v4 := ip.To4(); v4 != nil {
		family = 0
		ip = v4
	}
	node := f.roots[family]
	var number uint32
	for i := 0; node != nil; i++ {
		if node.number != 0 {
			number = node.number
		}
		if i == len(ip)*8 {
			break
		}
		node = node.children[(ip[i/8]>>uint(7-i%8))&1]
	}
	return number
}

// IsAllowed never grants a bypass to unknown or malformed addresses.
func (f *ASNFilter) IsAllowed(address string) bool {
	return f != nil && f.allowed[f.Lookup(address)]
}
