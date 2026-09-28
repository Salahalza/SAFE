package behavior

import (
	"reflect"
	"testing"
)

// TestSortHitsDeterministic proves SortHits is a pure function of the hit set:
// two different input orderings of the same hits sort to an identical slice.
// This is the property that makes behavior_hits.csv byte-for-byte reproducible
// across analyze runs even though rules emit hits in map-iteration order.
func TestSortHitsDeterministic(t *testing.T) {
	// Several hits that collide on (severity, RuleID) — the exact case the old
	// two-field tiebreaker left in arbitrary order.
	base := []Hit{
		{RuleID: "B-01", Severity: "NOTABLE", TimelineSearchKey: "task-c", EvidenceDetail: "c"},
		{RuleID: "B-01", Severity: "NOTABLE", TimelineSearchKey: "task-a", EvidenceDetail: "a"},
		{RuleID: "B-01", Severity: "NOTABLE", TimelineSearchKey: "task-b", EvidenceDetail: "b"},
		{RuleID: "IIS-02", Severity: "HIGH", TimelineSearchKey: "shell-2", EvidenceSource: "web_files.csv"},
		{RuleID: "IIS-02", Severity: "HIGH", TimelineSearchKey: "shell-1", EvidenceSource: "web_files.csv"},
		{RuleID: "B-10", Severity: "INFO", TimelineSearchKey: "z"},
	}

	// A reversed copy — a different starting order for the same set.
	reversed := make([]Hit, len(base))
	for i := range base {
		reversed[i] = base[len(base)-1-i]
	}

	SortHits(base)
	SortHits(reversed)

	if !reflect.DeepEqual(base, reversed) {
		t.Fatalf("SortHits not order-independent:\n from-forward: %+v\n from-reverse: %+v", base, reversed)
	}

	// Severity precedence: HIGH first, INFO last, regardless of input.
	if base[0].Severity != "HIGH" {
		t.Errorf("expected HIGH hit first, got %q", base[0].Severity)
	}
	if base[len(base)-1].Severity != "INFO" {
		t.Errorf("expected INFO hit last, got %q", base[len(base)-1].Severity)
	}

	// Within the tied B-01 group, TimelineSearchKey breaks the tie ascending.
	var b01Keys []string
	for _, h := range base {
		if h.RuleID == "B-01" {
			b01Keys = append(b01Keys, h.TimelineSearchKey)
		}
	}
	want := []string{"task-a", "task-b", "task-c"}
	if !reflect.DeepEqual(b01Keys, want) {
		t.Errorf("B-01 group not ordered by TimelineSearchKey: got %v want %v", b01Keys, want)
	}
}

// TestSortHitsUnknownSeverityLast guards the fallback: a hit with an
// unrecognized severity must never sort above a real HIGH.
func TestSortHitsUnknownSeverityLast(t *testing.T) {
	hits := []Hit{
		{RuleID: "X-01", Severity: "WEIRD"},
		{RuleID: "A-01", Severity: "HIGH"},
	}
	SortHits(hits)
	if hits[0].Severity != "HIGH" {
		t.Fatalf("expected HIGH first, got %q", hits[0].Severity)
	}
}
