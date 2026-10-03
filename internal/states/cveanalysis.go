package states

import (
	"context"
	"fmt"

	"github.com/fedorovmv/izyan/internal/cveanalysis"
	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/justification"
	"github.com/fedorovmv/izyan/internal/llm"
)

// ActResearchCVE performs autonomous research and synthesizes the technical justification.
func ActResearchCVE(ctx context.Context, c *domain.AnalysisCase, resolver cveanalysis.SourceResolver, client llm.Completer) error {
	if c.CVEAnalysisProfile == domain.ProfileOff || c.CVEAnalysisProfile == "" {
		return nil
	}

	if resolver != nil {
		bundle, err := resolver.Resolve(ctx, c)
		if err == nil {
			c.CVEAnalysisBundle = &bundle
		}
	}

	if isNilClient(client) {
		if c.StrictLLM {
			return fmt.Errorf("strict-llm: llm client is required for cve analysis")
		}
		dossier := justification.Build(c)
		c.Justification = &dossier
		return nil
	}

	runner := cveanalysis.NewToolRunner()
	researcher := llm.NewResearcher(client, runner, 8)
	proposal, err := researcher.Research(ctx, c)
	if err != nil {
		if c.StrictLLM {
			return fmt.Errorf("strict-llm: cve research failed: %w", err)
		}
	} else {
		c.CVEAnalysis = &proposal

		// Strategy planning
		planner := llm.NewStrategyPlanner(client)
		plan, perr := planner.Plan(ctx, c)
		if perr != nil {
			if c.StrictLLM {
				return fmt.Errorf("strict-llm: strategy planning failed: %w", perr)
			}
		} else {
			c.StrategyPlan = &plan
		}

		// Semantic mechanism review (Gate A2)
		reviewer := llm.NewMechanismReviewer(client)
		rev, rerr := reviewer.Review(ctx, c, proposal)
		if rerr != nil {
			if c.StrictLLM {
				return fmt.Errorf("strict-llm: mechanism review failed: %w", rerr)
			}
		} else {
			c.SemanticReview = &rev
			if c.CVEAnalysisProfile == domain.ProfileVerified && rev.Passed {
				c.AcceptLocusProposals = true
			}
		}
	}

	dossier := justification.Build(c)
	c.Justification = &dossier
	return nil
}

func isNilClient(c llm.Completer) bool {
	if c == nil {
		return true
	}
	if cl, ok := c.(*llm.Client); ok && cl == nil {
		return true
	}
	return false
}
