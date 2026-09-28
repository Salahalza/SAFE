package ioc

import (
	"testing"
)

func TestIsBenignIP(t *testing.T) {
	tests := []struct {
		ip       string
		expected bool
	}{
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"10.5.2.1", true},
		{"192.168.1.100", true},
		{"172.16.5.5", true},
		{"127.0.0.1", true},
		{"169.254.1.1", true},
		{"invalid-ip", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			got := IsBenignIP(tt.ip)
			if got != tt.expected {
				t.Errorf("IsBenignIP(%q) = %v; want %v", tt.ip, got, tt.expected)
			}
		})
	}
}

func TestIsBenignDomain(t *testing.T) {
	tests := []struct {
		domain   string
		expected bool
	}{
		{"google.com", true},
		{"mail.google.com", true},
		{"microsoft.com", true},
		{"update.microsoft.com", true},
		{"windowsupdate.com", true},
		{"github.com", false},
		{"apple.com", true},
		{"amazon.com", true},
		{"evil.com", false},
		{"suspicious.net", false},
		{"sub.evil.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			got := IsBenignDomain(tt.domain)
			if got != tt.expected {
				t.Errorf("IsBenignDomain(%q) = %v; want %v", tt.domain, got, tt.expected)
			}
		})
	}
}
