package ioc

import (
	"os"
	"strings"
	"testing"

	"time"
)

// ─── refangText ───────────────────────────────────────────────────────────────

func TestRefangText(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		// Standard lower-case
		{"hxxp://example.com", "http://example.com"},
		{"hxxps://secure.com", "https://secure.com"},
		// Upper-case (ENH 3)
		{"HXXP://EXAMPLE.COM", "http://EXAMPLE.COM"},
		{"HXXPS://EVIL.COM/path", "https://EVIL.COM/path"},
		// Mixed case variants (ENH 3)
		{"Hxxp://mixed.com", "http://mixed.com"},
		{"hXXP://another.com", "http://another.com"},
		// Dot-bracket variants
		{"evil[.]com", "evil.com"},
		{"bad(.)net", "bad.net"},
		// Email at variants
		{"admin[at]corp.local", "admin@corp.local"},
		{"admin(at)corp.local", "admin@corp.local"},
		// Chained defanging
		{"hxxps://evil[.]com/drop", "https://evil.com/drop"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := refangText(tt.input)
			if got != tt.expected {
				t.Errorf("refangText(%q) = %q; want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// ─── extractContext ───────────────────────────────────────────────────────────

func TestExtractContext(t *testing.T) {
	text := "This is a long sentence with an IP 8.8.8.8 inside it."
	start := strings.Index(text, "8.8.8.8")
	end := start + len("8.8.8.8")

	t.Run("padding within bounds", func(t *testing.T) {
		got := extractContext(text, start, end, 10)
		if !strings.Contains(got, "8.8.8.8") {
			t.Errorf("context should contain the IOC value, got: %q", got)
		}
	})

	t.Run("padding exceeds length returns full text", func(t *testing.T) {
		got := extractContext(text, start, end, 1000)
		if got != text {
			t.Errorf("expected full text, got: %q", got)
		}
	})

	t.Run("start at zero", func(t *testing.T) {
		got := extractContext(text, 0, 4, 5)
		if !strings.Contains(got, "This") {
			t.Errorf("expected beginning of text, got: %q", got)
		}
	})

	t.Run("newlines are cleaned up", func(t *testing.T) {
		multiline := "line1\nmalware.com\r\nline3"
		idx := strings.Index(multiline, "malware.com")
		got := extractContext(multiline, idx, idx+11, 5)
		if strings.ContainsAny(got, "\r\n") {
			t.Errorf("context should not contain raw newlines, got: %q", got)
		}
	})
}

// ─── ExtractFromFile (text) ──────────────────────────────────────────────────

func TestExtractFromFile_TextFile(t *testing.T) {
	t.Run("missing file returns error", func(t *testing.T) {
		_, err := ExtractFromFile("does_not_exist.txt")
		if err == nil {
			t.Error("expected error for missing file, got nil")
		}
	})
}

// ─── IPv4 extraction edge cases ──────────────────────────────────────────────

func extractText(text string) *ExtractionResult {
	// Write text to a temp file and run extraction.
	f, _ := os.CreateTemp("", "ioc-test-*.txt")
	defer func() { _ = os.Remove(f.Name()) }()
	_, _ = f.WriteString(text)
	_ = f.Close()
	result, _ := ExtractFromFile(f.Name())
	return result
}

func TestIPv4EdgeCases(t *testing.T) {
	t.Run("valid external IP is extracted", func(t *testing.T) {
		r := extractText("C2 server at 13.44.55.66 was observed.")
		if !containsIOC(r, "ipv4-addr", "13.44.55.66") {
			t.Error("expected 13.44.55.66 to be extracted")
		}
	})

	t.Run("invalid octet 999.999.999.999 is rejected", func(t *testing.T) {
		r := extractText("Bad IP 999.999.999.999 in report.")
		if containsIOC(r, "ipv4-addr", "999.999.999.999") {
			t.Error("999.999.999.999 should be rejected as invalid IP")
		}
	})

	t.Run("0.0.0.0 is suppressed", func(t *testing.T) {
		r := extractText("Bound to 0.0.0.0 for listening.")
		if containsIOC(r, "ipv4-addr", "0.0.0.0") {
			t.Error("0.0.0.0 should be benign/suppressed")
		}
	})

	t.Run("255.255.255.255 broadcast is suppressed", func(t *testing.T) {
		r := extractText("Broadcast to 255.255.255.255.")
		if containsIOC(r, "ipv4-addr", "255.255.255.255") {
			t.Error("255.255.255.255 should be suppressed as broadcast")
		}
	})

	t.Run("internal 10.x.x.x is suppressed", func(t *testing.T) {
		r := extractText("Internal host 10.20.30.40.")
		if containsIOC(r, "ipv4-addr", "10.20.30.40") {
			t.Error("RFC1918 address should be suppressed")
		}
	})

	t.Run("IP inside URL is not double-extracted as ipv4-addr", func(t *testing.T) {
		r := extractText("Payload dropped from http://23.44.55.66/evil.exe")
		// Should have URL IOC
		if !containsIOCType(r, "url") {
			t.Error("expected url IOC for IP-based URL")
		}
		// Should NOT have a bare ipv4-addr for the same IP
		if containsIOC(r, "ipv4-addr", "23.44.55.66") {
			t.Error("IP inside URL should not be extracted as bare ipv4-addr (ENH 2)")
		}
	})
}

// ─── Hash extraction edge cases ───────────────────────────────────────────────

func TestHashEdgeCases(t *testing.T) {
	sha256 := "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	sha1 := "aabbccddeeff00112233445566778899aabbccdd"
	md5 := "aabbccddeeff00112233445566778899"

	t.Run("SHA-256 is extracted correctly", func(t *testing.T) {
		r := extractText("Malware hash: " + sha256)
		if !containsIOC(r, "file", sha256) {
			t.Errorf("expected SHA-256 %s to be extracted", sha256)
		}
	})

	t.Run("SHA-256 does NOT produce phantom MD5 (BUG 1)", func(t *testing.T) {
		r := extractText("Malware hash: " + sha256)
		// The first 32 chars of sha256 should NOT appear as an MD5
		prefix32 := sha256[:32]
		if containsIOC(r, "file", prefix32) {
			t.Errorf("SHA-256 prefix %q was incorrectly extracted as MD5 (BUG 1 regression)", prefix32)
		}
	})

	t.Run("SHA-1 is extracted", func(t *testing.T) {
		r := extractText("File SHA1: " + sha1)
		if !containsIOC(r, "file", sha1) {
			t.Errorf("expected SHA-1 %s to be extracted (ENH 1)", sha1)
		}
	})

	t.Run("MD5 is extracted when standalone", func(t *testing.T) {
		r := extractText("Dropper MD5: " + md5)
		if !containsIOC(r, "file", md5) {
			t.Errorf("expected MD5 %s to be extracted", md5)
		}
	})

	t.Run("when SHA-256 and MD5 both present, both extracted separately", func(t *testing.T) {
		r := extractText("SHA256: " + sha256 + " MD5: " + md5)
		if !containsIOC(r, "file", sha256) {
			t.Error("SHA-256 should be extracted")
		}
		if !containsIOC(r, "file", md5) {
			t.Error("standalone MD5 should still be extracted")
		}
	})
}

// ─── Domain extraction edge cases ────────────────────────────────────────────

func TestDomainEdgeCases(t *testing.T) {
	t.Run("valid malicious domain is extracted", func(t *testing.T) {
		r := extractText("Beacon calling home to malware.ru")
		if !containsIOC(r, "domain-name", "malware.ru") {
			t.Error("expected malware.ru to be extracted")
		}
	})

	t.Run(".dll file extension is not treated as TLD (BUG 3)", func(t *testing.T) {
		r := extractText("Loaded module kernel32.dll from system32.")
		if containsIOC(r, "domain-name", "kernel32.dll") {
			t.Error("kernel32.dll should not be extracted as a domain (BUG 3 regression)")
		}
	})

	t.Run(".exe file extension is not treated as TLD (BUG 3)", func(t *testing.T) {
		r := extractText("Malicious binary svchost.exe was found.")
		if containsIOC(r, "domain-name", "svchost.exe") {
			t.Error("svchost.exe should not be extracted as a domain (BUG 3 regression)")
		}
	})

	t.Run("version numbers are not extracted as domains (BUG 3)", func(t *testing.T) {
		r := extractText("Python version 3.11.2 was found.")
		if containsIOC(r, "domain-name", "3.11.2") {
			t.Error("version number 3.11.2 should not be extracted as a domain")
		}
	})

	t.Run("benign domain google.com is suppressed", func(t *testing.T) {
		r := extractText("Queried google.com for DNS resolution.")
		if containsIOC(r, "domain-name", "google.com") {
			t.Error("google.com should be suppressed as benign")
		}
	})

	t.Run("subdomain of benign domain is suppressed", func(t *testing.T) {
		r := extractText("Connecting to update.microsoft.com.")
		if containsIOC(r, "domain-name", "update.microsoft.com") {
			t.Error("update.microsoft.com should be suppressed (subdomain of microsoft.com)")
		}
	})

	t.Run("github.com is NOT suppressed", func(t *testing.T) {
		r := extractText("Raw payload pulled from github.com/evil/repo.")
		if !containsIOC(r, "domain-name", "github.com") {
			t.Error("github.com should be extractable (C2 abuse via GitHub is real)")
		}
	})

	t.Run("domain inside URL is not double-extracted (BUG 4)", func(t *testing.T) {
		r := extractText("Loader fetched http://evil.com/stage2.bin")
		if containsIOC(r, "domain-name", "evil.com") {
			t.Error("evil.com should not be extracted separately when it is inside a URL (BUG 4 regression)")
		}
		if !containsIOCType(r, "url") {
			t.Error("expected url IOC for http://evil.com/stage2.bin")
		}
	})
}

// ─── URL extraction ───────────────────────────────────────────────────────────

func TestURLExtraction(t *testing.T) {
	t.Run("http URL is extracted (BUG 5)", func(t *testing.T) {
		r := extractText("Payload at http://c2.badguy.net/drop")
		if !containsIOCType(r, "url") {
			t.Error("expected url IOC (BUG 5 regression)")
		}
	})

	t.Run("defanged URL is refanged then extracted", func(t *testing.T) {
		r := extractText("hxxps://evil[.]com/payload.bin")
		if !containsIOCType(r, "url") {
			t.Error("expected url IOC from defanged hxxps URL")
		}
	})
}

// ─── Deduplication ───────────────────────────────────────────────────────────

func TestDeduplication(t *testing.T) {
	r := extractText("13.44.55.66 was seen. Then 13.44.55.66 again. And 13.44.55.66 once more.")
	count := 0
	for _, ioc := range r.IOCs {
		if ioc.Type == "ipv4-addr" && ioc.Value == "13.44.55.66" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 deduplicated entry for 13.44.55.66, got %d", count)
	}
}

// ─── ToSTIXBundle ─────────────────────────────────────────────────────────────

func TestToSTIXBundle_Empty(t *testing.T) {
	r := &ExtractionResult{SourceFile: "test.txt", IOCs: nil}
	bundle, err := r.ToSTIXBundle(time.Now())
	if err != nil {
		t.Fatalf("unexpected error for empty IOC list: %v", err)
	}
	if bundle == nil {
		t.Fatal("bundle should not be nil (BUG 8)")
	}
}

// ─── helpers ──────────────────────────────────────────────────────────────────

func containsIOC(r *ExtractionResult, iocType, value string) bool {
	if r == nil {
		return false
	}
	for _, c := range r.IOCs {
		if c.Type == iocType && c.Value == value {
			return true
		}
	}
	return false
}

func containsIOCType(r *ExtractionResult, iocType string) bool {
	if r == nil {
		return false
	}
	for _, c := range r.IOCs {
		if c.Type == iocType {
			return true
		}
	}
	return false
}
