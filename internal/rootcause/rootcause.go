// Package rootcause automates RootCauseModel construction without an LLM:
// candidates come from authoritative sources (advisory symbols, fix patch)
// and are verified against the actual source tree before being trusted.
package rootcause

import (
	"context"
	"fmt"
	"strings"

	"example.com/vuln-analyzer/internal/domain"
	"example.com/vuln-analyzer/internal/fix"
	"example.com/vuln-analyzer/internal/goanalysis"
)

// Resolver produces root-cause candidates from advisory data and the fix
// patch, following the spec priority: affected symbols first, then the fix
// commit diff.
type Resolver struct {
	Fix   fix.Resolver
	Patch fix.Provider // optional; nil disables patch-based candidates
}

// maxPatchFiles bounds the patch scope we accept before calling the result
// ambiguous — a giant refactor diff does not pinpoint a root cause.
const maxPatchFiles = 8

func (r Resolver) Resolve(ctx context.Context, _ *domain.AnalysisCase, v domain.Vulnerability) (*domain.RootCauseModel, []domain.Evidence, error) {
	model := &domain.RootCauseModel{Status: domain.RootCauseNotFound}
	var evs []domain.Evidence

	// Priority 1: affected symbols named by the advisory.
	for _, s := range v.AffectedSymbols {
		model.RootCauses = append(model.RootCauses, domain.RootCause{
			Package:   s.Package,
			Symbol:    s.Symbol,
			Role:      domain.RootCauseSink,
			Mechanism: "advisory-listed affected symbol",
		})
	}
	if len(model.RootCauses) > 0 {
		evs = append(evs, domain.Evidence{
			Kind:    domain.EvidenceAdvisory,
			Quality: domain.QualityAuthoritative,
			Source:  "advisory affected symbols",
			Tool:    "vulnerability.OSV",
			Content: symbolList(v.AffectedSymbols),
		})
	}

	// Priority 2: functions changed by the fix commit.
	for _, ref := range r.Fix.Resolve(v) {
		if r.Patch == nil {
			model.Limitations = append(model.Limitations, "patch provider not configured; fix diff not analyzed")
			break
		}
		patch, err := r.Patch.Fetch(ctx, ref)
		if err != nil {
			model.Limitations = append(model.Limitations, "fix patch fetch failed: "+err.Error())
			continue
		}
		evs = append(evs, domain.Evidence{
			Kind:    domain.EvidenceFixDiff,
			Quality: domain.QualityAuthoritative,
			Source:  ref.URL,
			Tool:    "fix.HTTPProvider",
			Content: truncate(patch, 64<<10),
		})
		for _, f := range fix.Parse(patch) {
			if !strings.HasSuffix(f.Path, ".go") {
				continue
			}
			if isTestFile(f.Path) {
				continue
			}
			for _, sym := range f.Symbols {
				model.Alternatives = append(model.Alternatives, domain.RootCause{
					Package:   packageGuess(v, f.Path),
					Symbol:    sym,
					Role:      domain.RootCauseSink,
					Mechanism: fmt.Sprintf("changed by fix commit %s", ref.URL),
				})
			}
		}
		if len(model.Alternatives) > 0 && len(model.RootCauses) == 0 {
			model.RootCauses = model.Alternatives
			model.Alternatives = nil
		}
		break // one authoritative patch is enough
	}

	if len(model.RootCauses) == 0 {
		return model, evs, nil
	}
	model.Status = domain.RootCauseResolved
	return model, evs, nil
}

func symbolList(syms []domain.SymbolRef) string {
	parts := make([]string, 0, len(syms))
	for _, s := range syms {
		parts = append(parts, s.Package+"."+s.Symbol)
	}
	return strings.Join(parts, "\n")
}

// packageGuess maps a repo-relative path to the affected package path when
// possible (suffix match on the module path tail).
func packageGuess(v domain.Vulnerability, filePath string) string {
	// fall back: module root file
	if !strings.Contains(filePath, "/") {
		return v.Module
	}
	dir := filePath[:strings.LastIndexByte(filePath, '/')]
	for _, p := range v.AffectedPackages {
		if strings.HasSuffix(dir, strings.TrimPrefix(p.Path, v.Module+"/")) ||
			strings.HasSuffix(p.Path, dir) || p.Path == dir {
			return p.Path
		}
	}
	return v.Module + "/" + dir
}

func isTestFile(p string) bool { return strings.HasSuffix(p, "_test.go") }

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "\n...[truncated]"
}

// Verifier checks candidates against the analyzed source: the symbol must
// exist in the module cache / replaced dependency and belong to an affected
// package. Unverified candidates are dropped into Alternatives.
type Verifier struct {
	Source *goanalysis.Index
}

func (vf Verifier) Verify(ctx context.Context, m *domain.RootCauseModel, v domain.Vulnerability) []string {
	var limitations []string
	if vf.Source == nil {
		return []string{"root-cause verifier has no source index; candidates unverified"}
	}
	verified := make([]domain.RootCause, 0, len(m.RootCauses))
	for _, rc := range m.RootCauses {
		if !inAffectedPackages(rc, v) {
			m.Alternatives = append(m.Alternatives, rc)
			continue
		}
		_, err := vf.Source.FindSymbol(ctx, domain.SymbolRef{Package: rc.Package, Symbol: rc.Symbol})
		if err != nil {
			limitations = append(limitations,
				fmt.Sprintf("candidate %s.%s not found in source: %v", rc.Package, rc.Symbol, err))
			m.Alternatives = append(m.Alternatives, rc)
			continue
		}
		verified = append(verified, rc)
	}
	m.RootCauses = verified
	if len(verified) == 0 && len(m.Alternatives) > 0 {
		m.Status = domain.RootCauseAmbiguous
		m.RootCauses = nil
	}
	return limitations
}

func inAffectedPackages(rc domain.RootCause, v domain.Vulnerability) bool {
	if len(v.AffectedPackages) == 0 {
		return true // no constraint recorded
	}
	for _, p := range v.AffectedPackages {
		if p.Path == rc.Package {
			return true
		}
	}
	return false
}
