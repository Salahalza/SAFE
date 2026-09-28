package tier3

import (
	"fmt"
	"path/filepath"
	"github.com/Salahalza/SAFE/internal/analyzer/timeline"
	"github.com/Salahalza/SAFE/internal/behavior"
)

// RunEngine executes Tier 3 sequential rules over the timeline.
func RunEngine(labReportDir string) ([]behavior.Hit, error) {
	// T3-01 (ExecutionToNetwork) and T3-02 (NetworkToExecution) are intentionally
	// NOT registered. Both correlate execution with network *connections*, but
	// SAFE ingests no network-connection events into the timeline (there is no
	// netstat / Sysmon EID-3 collection), so they can never fire on any real case.
	// Their code is kept in rules.go — documented and ready to enable if a
	// network-event source is ever added — rather than deleted, but running them
	// live would read as cross-artifact coverage that does not actually exist.
	rules := []Rule{
		NewLateralMovementToExecutionRule(),
		NewSuspiciousProcessLineageRule(),
	}

	timelinePath := filepath.Join(labReportDir, "timeline.csv")
	ch := make(chan timeline.Event, 100)

	// Start streaming
	var streamErr error
	go func() {
		streamErr = timeline.Stream(timelinePath, ch)
	}()

	var allHits []behavior.Hit

	for event := range ch {
		for _, rule := range rules {
			hits := rule.Process(event)
			if len(hits) > 0 {
				allHits = append(allHits, hits...)
			}
		}
	}

	if streamErr != nil {
		return nil, fmt.Errorf("timeline stream error: %w", streamErr)
	}

	for _, rule := range rules {
		hits := rule.Flush()
		if len(hits) > 0 {
			allHits = append(allHits, hits...)
		}
	}

	// Sort hits through the shared total-order comparator so the intermediate
	// ordering is deterministic (WriteHits re-sorts the merged set the same way).
	behavior.SortHits(allHits)

	return allHits, nil
}
