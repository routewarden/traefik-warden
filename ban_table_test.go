package traefik_warden

import (
	"testing"
	"time"
)

func TestBanTable_Basic(t *testing.T) {
	bt := NewBanTable(100)

	if bt.IsBanned("192.0.2.1") {
		t.Errorf("expected 192.0.2.1 to not be banned initially")
	}

	bt.Ban("192.0.2.1:12345", 50*time.Millisecond)

	if !bt.IsBanned("192.0.2.1") {
		t.Errorf("expected 192.0.2.1 to be banned after adding")
	}
	if !bt.IsBanned("192.0.2.1:54321") {
		t.Errorf("expected 192.0.2.1 with different port to be recognized as banned")
	}

	time.Sleep(60 * time.Millisecond)
	if bt.IsBanned("192.0.2.1") {
		t.Errorf("expected 192.0.2.1 ban to have expired")
	}
}

func TestBanTable_IPv6(t *testing.T) {
	bt := NewBanTable(100)

	ipv6 := "[2001:db8::1]:443"
	bt.Ban(ipv6, 1*time.Minute)

	if !bt.IsBanned("2001:db8::1") {
		t.Errorf("expected 2001:db8::1 to be banned")
	}
	if !bt.IsBanned("[2001:db8::1]") {
		t.Errorf("expected [2001:db8::1] to be banned")
	}
}

func TestBanTable_IPv4MappedIPv6(t *testing.T) {
	bt := NewBanTable(100)

	// Ban via standard IPv4
	bt.Ban("192.0.2.1", 1*time.Minute)

	// Check dual-stack IPv4-mapped IPv6 formats
	if !bt.IsBanned("::ffff:192.0.2.1") {
		t.Errorf("expected ::ffff:192.0.2.1 to be recognized as banned")
	}
	if !bt.IsBanned("[::ffff:192.0.2.1]:12345") {
		t.Errorf("expected [::ffff:192.0.2.1]:12345 to be recognized as banned")
	}

	// Ban via IPv4-mapped IPv6, check via standard IPv4
	bt2 := NewBanTable(100)
	bt2.Ban("[::ffff:198.51.100.22]:8080", 1*time.Minute)
	if !bt2.IsBanned("198.51.100.22") {
		t.Errorf("expected 198.51.100.22 to be recognized as banned when added via mapped IPv6")
	}
}

func TestBanTable_Capacity(t *testing.T) {
	bt := NewBanTable(2)

	bt.Ban("192.0.2.1", 10*time.Millisecond)
	bt.Ban("192.0.2.2", 1*time.Minute)
	time.Sleep(15 * time.Millisecond)

	// Adding third should evict the expired 192.0.2.1
	bt.Ban("192.0.2.3", 1*time.Minute)

	if bt.IsBanned("192.0.2.1") {
		t.Errorf("expected 192.0.2.1 to be evicted")
	}
	if !bt.IsBanned("192.0.2.2") {
		t.Errorf("expected 192.0.2.2 to remain banned")
	}
	if !bt.IsBanned("192.0.2.3") {
		t.Errorf("expected 192.0.2.3 to be banned")
	}
}

func TestParseBanDuration(t *testing.T) {
	tests := []struct {
		input    string
		expected time.Duration
	}{
		{"", 24 * time.Hour},
		{"1h", 1 * time.Hour},
		{"30m", 30 * time.Minute},
		{"86400", 24 * time.Hour},
		{"60", 60 * time.Second},
		{"invalid", 24 * time.Hour},
	}

	for _, tt := range tests {
		got := ParseBanDuration(tt.input)
		if got != tt.expected {
			t.Errorf("ParseBanDuration(%q) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}

