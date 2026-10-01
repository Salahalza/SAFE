package ioc

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/TcM1911/stix2"
	"github.com/ledongthuc/pdf"
)

// IOCCandidate represents an extracted indicator with context.
type IOCCandidate struct {
	Type       string // ipv4-addr, domain-name, url, file
	Value      string
	Context    string
	Confidence int // 0-100
}

// ExtractionResult represents the outcome of parsing a threat report.
type ExtractionResult struct {
	SourceFile string
	RawText    string
	IOCs       []IOCCandidate
}

// nonDomainExts lists file extensions that the domain regex should never accept as a TLD.
var nonDomainExts = map[string]bool{
	"dll": true, "exe": true, "sys": true, "log": true, "txt": true,
	"json": true, "csv": true, "xml": true, "tmp": true, "bat": true,
	"ps1": true, "cmd": true, "lnk": true, "iso": true, "zip": true,
	"rar": true, "7z": true, "cab": true, "msi": true, "mui": true,
	"pdb": true, "manifest": true, "cfg": true, "ini": true,
	// Windows forensic artifact extensions — must never be treated as TLDs.
	"dit": true, "etl": true, "evtx": true, "hive": true,
}

// ENH 3 — case-insensitive regex-based refanger for all hxxp variants.
var (
	reHxxp = regexp.MustCompile(`(?i)hxxps?://`)
	reDot  = regexp.MustCompile(`\[\.\]|\(\.\)`)
	reAt   = regexp.MustCompile(`\[at\]|\(at\)`)
)

// refangText normalizes common defanging techniques used in DFIR reports.
func refangText(text string) string {
	// hxxp:// / HXXP:// / hxxps:// / HXXPS:// (case-insensitive, ENH 3)
	text = reHxxp.ReplaceAllStringFunc(text, func(m string) string {
		m = strings.ToLower(m)
		return strings.Replace(m, "hxxp", "http", 1)
	})
	// [.] and (.) → .
	text = reDot.ReplaceAllString(text, ".")
	// [at] and (at) → @
	text = reAt.ReplaceAllString(text, "@")
	return text
}

// extractContext extracts a padded text snippet surrounding the match.
func extractContext(text string, start, end, padding int) string {
	s := start - padding
	if s < 0 {
		s = 0
	}
	e := end + padding
	if e > len(text) {
		e = len(text)
	}
	snippet := text[s:e]
	snippet = strings.ReplaceAll(snippet, "\r", " ")
	snippet = strings.ReplaceAll(snippet, "\n", " ")
	return strings.TrimSpace(snippet)
}

// ExtractFromFile reads a PDF or plain-text file and extracts IOC candidates.
// Supported extensions: .pdf (binary extraction), anything else (treated as UTF-8 text).
func ExtractFromFile(filePath string) (*ExtractionResult, error) {
	var text string

	if strings.ToLower(filepath.Ext(filePath)) == ".pdf" {
		var err error
		text, err = readPDFText(filePath)
		if err != nil {
			return nil, fmt.Errorf("read PDF: %w", err)
		}
	} else {
		// BUG 6 fix: use assignment (=) not short declaration (:=) to avoid shadowing outer err.
		var data []byte
		var err error
		data, err = os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("read text file: %w", err)
		}
		text = string(data)
	}

	text = refangText(text)

	var candidates []IOCCandidate

	// Track which regions of text are already consumed by a URL or IP match so
	// that the domain pass does not double-extract them (BUG 4 / ENH 2).
	type span struct{ s, e int }
	var consumedSpans []span

	inConsumed := func(s, e int) bool {
		for _, c := range consumedSpans {
			if s < c.e && e > c.s {
				return true
			}
		}
		return false
	}

	// ── PASS 1: URL extraction (BUG 5) ────────────────────────────────────────
	// Must run first so later passes can skip URL-internal tokens.
	urlRegex := regexp.MustCompile(`https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+`)
	for _, match := range urlRegex.FindAllStringIndex(text, -1) {
		val := text[match[0]:match[1]]
		// Strip trailing punctuation that crept in (e.g., URL followed by ")
		val = strings.TrimRight(val, `"').>,`)
		consumedSpans = append(consumedSpans, span{match[0], match[1]})
		candidates = append(candidates, IOCCandidate{
			Type:       "url",
			Value:      strings.ToLower(val),
			Context:    extractContext(text, match[0], match[1], 100),
			Confidence: 90,
		})
	}

	// ── PASS 2: IPv4 with octet-range validation (BUG 2) ─────────────────────
	ipRegex := regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	for _, match := range ipRegex.FindAllStringIndex(text, -1) {
		if inConsumed(match[0], match[1]) {
			continue // ENH 2: IP that is part of a URL is already captured
		}
		val := text[match[0]:match[1]]
		// BUG 2: validate octets via net.ParseIP
		if net.ParseIP(val) == nil {
			continue
		}
		if IsBenignIP(val) {
			continue
		}
		consumedSpans = append(consumedSpans, span{match[0], match[1]})
		candidates = append(candidates, IOCCandidate{
			Type:       "ipv4-addr",
			Value:      val,
			Context:    extractContext(text, match[0], match[1], 100),
			Confidence: 100,
		})
	}

	// ── PASS 3: SHA-256 (64-char hex) — must run BEFORE MD5 (BUG 1) ─────────
	sha256Regex := regexp.MustCompile(`\b[a-fA-F0-9]{64}\b`)
	sha256Matches := make(map[string]bool)
	for _, match := range sha256Regex.FindAllStringIndex(text, -1) {
		val := strings.ToLower(text[match[0]:match[1]])
		sha256Matches[val] = true
		consumedSpans = append(consumedSpans, span{match[0], match[1]})
		candidates = append(candidates, IOCCandidate{
			Type:       "file",
			Value:      val,
			Context:    extractContext(text, match[0], match[1], 100),
			Confidence: 80,
		})
	}

	// ── PASS 4: SHA-1 (40-char hex) — ENH 1 ─────────────────────────────────
	sha1Regex := regexp.MustCompile(`\b[a-fA-F0-9]{40}\b`)
	for _, match := range sha1Regex.FindAllStringIndex(text, -1) {
		if inConsumed(match[0], match[1]) {
			continue // skip if this 40-char run is inside a 64-char SHA-256 match
		}
		val := strings.ToLower(text[match[0]:match[1]])
		consumedSpans = append(consumedSpans, span{match[0], match[1]})
		candidates = append(candidates, IOCCandidate{
			Type:       "file",
			Value:      val,
			Context:    extractContext(text, match[0], match[1], 100),
			Confidence: 70,
		})
	}

	// ── PASS 5: MD5 (32-char hex) — AFTER SHA-256/SHA-1 (BUG 1) ─────────────
	md5Regex := regexp.MustCompile(`\b[a-fA-F0-9]{32}\b`)
	for _, match := range md5Regex.FindAllStringIndex(text, -1) {
		if inConsumed(match[0], match[1]) {
			continue // avoid matching a 32-char prefix of a SHA-256 or SHA-1
		}
		val := strings.ToLower(text[match[0]:match[1]])
		if sha256Matches[val] {
			continue // extra guard: skip if this exact string is already a SHA-256
		}
		consumedSpans = append(consumedSpans, span{match[0], match[1]})
		candidates = append(candidates, IOCCandidate{
			Type:       "file",
			Value:      val,
			Context:    extractContext(text, match[0], match[1], 100),
			Confidence: 50,
		})
	}

	// ── PASS 6: Domain names (BUG 3 + BUG 4) ─────────────────────────────────
	// Pattern requires at least one alphabetic-only TLD of 2–13 chars.
	domainRegex := regexp.MustCompile(`\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+([a-zA-Z]{2,13})\b`)
	for _, match := range domainRegex.FindAllStringIndex(text, -1) {
		if inConsumed(match[0], match[1]) {
			continue // skip domains already inside a URL or IP span
		}
		val := strings.ToLower(strings.TrimRight(text[match[0]:match[1]], "."))

		// BUG 3: block known non-domain file/PE extensions used as TLD
		tld := val[strings.LastIndex(val, ".")+1:]
		if nonDomainExts[tld] {
			continue
		}

		// Skip pure numeric TLDs (version numbers like 1.0.4)
		allNumeric := true
		for _, ch := range tld {
			if ch < '0' || ch > '9' {
				allNumeric = false
				break
			}
		}
		if allNumeric {
			continue
		}

		if IsBenignDomain(val) {
			continue
		}

		candidates = append(candidates, IOCCandidate{
			Type:       "domain-name",
			Value:      val,
			Context:    extractContext(text, match[0], match[1], 100),
			Confidence: 80,
		})
	}

	// ── Deduplicate ────────────────────────────────────────────────────────────
	seen := make(map[string]bool)
	var uniqueIOCs []IOCCandidate
	for _, c := range candidates {
		key := c.Type + ":" + c.Value
		if !seen[key] {
			seen[key] = true
			uniqueIOCs = append(uniqueIOCs, c)
		}
	}

	return &ExtractionResult{
		SourceFile: filePath,
		RawText:    text,
		IOCs:       uniqueIOCs,
	}, nil
}

// readPDFText extracts raw text from a PDF file.
func readPDFText(path string) (string, error) {
	f, r, err := pdf.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	var buf bytes.Buffer
	b, err := r.GetPlainText()
	if err != nil {
		return "", err
	}
	if _, err := buf.ReadFrom(b); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// ToSTIXBundle converts the extraction result to a STIX 2.1 bundle.
// validFrom sets the valid_from field on every indicator — it should reflect
// the threat report's publication date, not the ingestion timestamp.
// BUG 8: returns an empty bundle (not an error) when there are no IOCs.
func (r *ExtractionResult) ToSTIXBundle(validFrom time.Time) (*stix2.Bundle, error) {
	if len(r.IOCs) == 0 {
		return stix2.NewBundle()
	}

	var indicators []stix2.STIXObject

	for _, ioc := range r.IOCs {
		var pattern, name string

		switch ioc.Type {
		case "ipv4-addr":
			pattern = fmt.Sprintf("[ipv4-addr:value = '%s']", ioc.Value)
			name = "IPv4 Indicator"
		case "domain-name":
			pattern = fmt.Sprintf("[domain-name:value = '%s']", ioc.Value)
			name = "Domain Indicator"
		case "url":
			pattern = fmt.Sprintf("[url:value = '%s']", ioc.Value)
			name = "URL Indicator"
		case "file":
			switch len(ioc.Value) {
			case 32:
				pattern = fmt.Sprintf("[file:hashes.MD5 = '%s']", ioc.Value)
				name = "MD5 File Hash"
			case 40:
				pattern = fmt.Sprintf("[file:hashes.'SHA-1' = '%s']", ioc.Value)
				name = "SHA-1 File Hash"
			case 64:
				pattern = fmt.Sprintf("[file:hashes.'SHA-256' = '%s']", ioc.Value)
				name = "SHA-256 File Hash"
			default:
				continue
			}
		default:
			continue
		}

		vf := &stix2.Timestamp{Time: validFrom}
		indicator, err := stix2.NewIndicator(pattern, "stix", vf,
			stix2.OptionName(name),
			stix2.OptionDescription(fmt.Sprintf("Context: ...%s...", ioc.Context)),
		)
		if err != nil {
			return nil, fmt.Errorf("create STIX indicator for %s: %w", ioc.Value, err)
		}

		indicators = append(indicators, indicator)
	}

	return stix2.NewBundle(indicators...)
}
