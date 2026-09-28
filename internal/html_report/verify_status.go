package html_report

import (
	"encoding/json"
	"net/http"
	"sync"

	"github.com/Salahalza/SAFE/internal/manifest"
)

// verifyStatus is the JSON the header integrity chip polls. Status is one of:
//   - "pending" — verification is still running (large cases hash every file);
//   - "ok"      — every file matched its recorded hash and nothing is unaccounted for;
//   - "failed"  — a mismatch, a missing file, or an unaccounted-for (planted) file;
//   - "error"   — verification could not run (e.g. no case manifest present).
//
// The counts let the chip report "Verified · N/N files" or an itemized failure
// without a second round-trip.
type verifyStatus struct {
	Status       string `json:"status"`
	FilesChecked int    `json:"files_checked"`
	Mismatches   int    `json:"mismatches"`
	Missing      int    `json:"missing"`
	Extra        int    `json:"extra"`
	Error        string `json:"error,omitempty"`
}

// verifyState holds the latest verification outcome behind a lock so the async
// startup verification can publish it while the /api/verify handler reads it.
type verifyState struct {
	mu     sync.RWMutex
	status verifyStatus
}

func newVerifyState() *verifyState {
	return &verifyState{status: verifyStatus{Status: "pending"}}
}

func (v *verifyState) get() verifyStatus {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.status
}

func (v *verifyState) set(s verifyStatus) {
	v.mu.Lock()
	v.status = s
	v.mu.Unlock()
}

// runVerify verifies the case folder once, at serve startup, in its own
// goroutine, and publishes the outcome for the header chip to poll. It runs
// async so hashing every collected file on a large case never blocks the report
// from loading (the chip shows "Verifying…" until this completes). Verifying on
// serve — rather than trusting a persisted `-verify` result — keeps the chip
// honest to the bytes actually being served. It is launched after the timeline
// SQLite cache is built, so the derived timeline.db (which manifest.Verify
// already excludes from its reconciliation) is settled before the walk.
func (s *Server) runVerify() {
	result, err := manifest.Verify(s.caseDir)
	if err != nil {
		s.verify.set(verifyStatus{Status: "error", Error: err.Error()})
		return
	}
	st := verifyStatus{
		FilesChecked: result.FilesChecked,
		Mismatches:   len(result.Mismatches),
		Missing:      len(result.Missing),
		Extra:        len(result.Extra),
	}
	if result.OK {
		st.Status = "ok"
	} else {
		st.Status = "failed"
	}
	s.verify.set(st)
}

// handleVerify returns the current verification state as JSON. The client polls
// it while the status is "pending".
func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(s.verify.get())
}
