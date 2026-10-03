package domain_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/fedorovmv/izyan/internal/domain"
)

func TestLegacyCaseDoesNotInventProof(t *testing.T) {
	var c domain.AnalysisCase
	legacyJSON := `{"id":"legacy-001","vulnerability":{"id":"GO-2099-0001"}}`
	if err := json.Unmarshal([]byte(legacyJSON), &c); err != nil {
		t.Fatalf("failed to unmarshal legacy case: %v", err)
	}
	if c.CVEAnalysisBundle != nil || c.CVEAnalysis != nil || c.Justification != nil {
		t.Fatal("legacy case unmarshaling invented unexpected CVE analysis artifacts")
	}
}

func TestCVEAnalysisDomainSerialization(t *testing.T) {
	bundle := domain.CVESourceBundle{
		Binding: domain.AnalysisBinding{
			AdvisoryID:      "GO-2026-6443",
			AdvisoryHash:    "sha256-adv",
			Module:          "google.golang.org/grpc",
			ResolvedVersion: "v1.80.0",
		},
		Artifacts: []domain.SourceArtifact{
			{
				ID:     "patch-01",
				Side:   "patch",
				URI:    "https://github.com/grpc/grpc-go/pull/9365.patch",
				Hash:   "sha256-patch",
				Status: "FETCHED",
			},
		},
		ManifestStatus: domain.ManifestComplete,
		FetchedAt:      time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC),
	}

	data, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal bundle failed: %v", err)
	}

	var restored domain.CVESourceBundle
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("unmarshal bundle failed: %v", err)
	}

	if restored.Binding.AdvisoryID != bundle.Binding.AdvisoryID {
		t.Errorf("got %q, want %q", restored.Binding.AdvisoryID, bundle.Binding.AdvisoryID)
	}
	if restored.ManifestStatus != domain.ManifestComplete {
		t.Errorf("got status %v, want COMPLETE", restored.ManifestStatus)
	}
}
