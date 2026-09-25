package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

type CaseID string
type EvidenceID string
type ConditionID string
type ClaimID string
type ReviewID string

type ClaimResult string

const (
	ClaimTrue    ClaimResult = "TRUE"
	ClaimFalse   ClaimResult = "FALSE"
	ClaimUnknown ClaimResult = "UNKNOWN"
)

type Verdict string

const (
	VerdictNotAffected        Verdict = "NOT_AFFECTED"
	VerdictExploitable        Verdict = "EXPLOITABLE"
	VerdictNoExploitPathFound Verdict = "NO_EXPLOIT_PATH_FOUND"
	VerdictInconclusive       Verdict = "INCONCLUSIVE"
)

type WorkflowState string

const (
	StateCreated              WorkflowState = "CREATED"
	StateSnapshotProduct      WorkflowState = "SNAPSHOT_PRODUCT"
	StateResolveVulnerability WorkflowState = "RESOLVE_VULNERABILITY"
	StateCheckAffected        WorkflowState = "CHECK_AFFECTED"
	StateResolveRootCause     WorkflowState = "RESOLVE_ROOT_CAUSE"
	StateBuildExploitModel    WorkflowState = "BUILD_EXPLOIT_MODEL"
	StateCollectEvidence      WorkflowState = "COLLECT_EVIDENCE"
	StateEvaluateConditions   WorkflowState = "EVALUATE_CONDITIONS"
	StateNegativeCheck        WorkflowState = "NEGATIVE_CHECK"
	StateReview               WorkflowState = "REVIEW"
	StateRepairAnalysis       WorkflowState = "REPAIR_ANALYSIS"
	StateEvaluateVerdict      WorkflowState = "EVALUATE_VERDICT"
	StateBuildReport          WorkflowState = "BUILD_REPORT"
	StateCompleted            WorkflowState = "COMPLETED"
	StateInconclusive         WorkflowState = "INCONCLUSIVE"
	StateFailed               WorkflowState = "FAILED"
)

type Vulnerability struct {
	ID               string            `json:"id"`
	Aliases          []string          `json:"aliases,omitempty"`
	Module           string            `json:"module,omitempty"`
	Package          string            `json:"package,omitempty"`
	AffectedVersions []VersionRange    `json:"affected_versions,omitempty"`
	FixedVersions    []string          `json:"fixed_versions,omitempty"`
	AffectedPackages []AffectedPackage `json:"affected_packages,omitempty"`
	AffectedSymbols  []SymbolRef       `json:"affected_symbols,omitempty"`
	Summary          string            `json:"summary,omitempty"`
	Description      string            `json:"description,omitempty"`
	CWE              []string          `json:"cwe,omitempty"`
	References       []Reference       `json:"references,omitempty"`
	Provenance       map[string]string `json:"provenance,omitempty"`
}

type VersionRange struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

type AffectedPackage struct {
	Path    string   `json:"path"`
	GOOS    []string `json:"goos,omitempty"`
	GOARCH  []string `json:"goarch,omitempty"`
	Symbols []string `json:"symbols,omitempty"`
}

type SymbolRef struct {
	Package string `json:"package"`
	Symbol  string `json:"symbol"`
}

type Reference struct {
	Type string `json:"type,omitempty"`
	URL  string `json:"url"`
}

type ProductSnapshot struct {
	Repository        string             `json:"repository"`
	Commit            string             `json:"commit"`
	GoVersion         string             `json:"go_version"`
	GOOS              string             `json:"goos"`
	GOARCH            string             `json:"goarch"`
	BuildTags         []string           `json:"build_tags,omitempty"`
	CGOEnabled        bool               `json:"cgo_enabled"`
	VendorMode        bool               `json:"vendor_mode"`
	GoWorkFile        string             `json:"go_work_file,omitempty"`
	ReplaceDirectives []ReplaceDirective `json:"replace_directives,omitempty"`
}

type ReplaceDirective struct {
	Old string `json:"old"`
	New string `json:"new"`
}

type AffectedResult struct {
	ModulePresent   ClaimResult  `json:"module_present"`
	ResolvedVersion string       `json:"resolved_version,omitempty"`
	VersionAffected ClaimResult  `json:"version_affected"`
	PackagePresent  ClaimResult  `json:"package_present"`
	BuildRelevant   ClaimResult  `json:"build_relevant"`
	EvidenceIDs     []EvidenceID `json:"evidence_ids,omitempty"`
	Limitations     []string     `json:"limitations,omitempty"`
}

type RootCauseStatus string

const (
	RootCauseResolved  RootCauseStatus = "RESOLVED"
	RootCauseAmbiguous RootCauseStatus = "AMBIGUOUS"
	RootCauseNotFound  RootCauseStatus = "NOT_FOUND"
)

type RootCauseRole string

const (
	RootCauseEntrypoint  RootCauseRole = "ENTRYPOINT"
	RootCausePropagation RootCauseRole = "PROPAGATION"
	RootCauseSink        RootCauseRole = "SINK"
)

type RootCause struct {
	Package     string        `json:"package"`
	Symbol      string        `json:"symbol"`
	Role        RootCauseRole `json:"role"`
	Mechanism   string        `json:"mechanism"`
	EvidenceIDs []EvidenceID  `json:"evidence_ids,omitempty"`
}

type RootCauseModel struct {
	Status       RootCauseStatus `json:"status"`
	RootCauses   []RootCause     `json:"root_causes"`
	Alternatives []RootCause     `json:"alternatives,omitempty"`
	Limitations  []string        `json:"limitations,omitempty"`
}

type ConditionKind string

const (
	ConditionSymbolReachable ConditionKind = "SYMBOL_REACHABLE"
	ConditionAttackerControl ConditionKind = "ATTACKER_CONTROL"
	ConditionInputConstraint ConditionKind = "INPUT_CONSTRAINT"
	ConditionValidation      ConditionKind = "VALIDATION"
	ConditionConfiguration   ConditionKind = "CONFIGURATION"
	ConditionBuild           ConditionKind = "BUILD_CONDITION"
	ConditionPlatform        ConditionKind = "PLATFORM_CONDITION"
	ConditionAuthn           ConditionKind = "AUTHENTICATION_CONDITION"
	ConditionRuntime         ConditionKind = "RUNTIME_CONDITION"
	ConditionCustom          ConditionKind = "CUSTOM"
)

type DataOrigin string

const (
	OriginExternalUntrusted     DataOrigin = "EXTERNAL_UNTRUSTED"
	OriginExternalAuthenticated DataOrigin = "EXTERNAL_AUTHENTICATED"
	OriginConfiguration         DataOrigin = "CONFIGURATION"
	OriginDatabase              DataOrigin = "DATABASE"
	OriginInternalService       DataOrigin = "INTERNAL_SERVICE"
	OriginConstant              DataOrigin = "CONSTANT"
	OriginGenerated             DataOrigin = "GENERATED"
	OriginUnknown               DataOrigin = "UNKNOWN"
)

type Condition struct {
	ID                ConditionID   `json:"id"`
	Kind              ConditionKind `json:"kind"`
	Description       string        `json:"description"`
	Mandatory         bool          `json:"mandatory"`
	Subject           *SymbolRef    `json:"subject,omitempty"`
	Subjects          []SymbolRef   `json:"subjects,omitempty"` // alternative symbols: condition holds if ANY is satisfied
	ArgIndex          int           `json:"arg_index,omitempty"`
	VerificationHints []string      `json:"verification_hints,omitempty"`
}

type ExploitModel struct {
	Impact              string       `json:"impact"`
	RootCauses          []SymbolRef  `json:"root_causes"`
	MandatoryConditions []Condition  `json:"mandatory_conditions"`
	SupportingFactors   []Condition  `json:"supporting_factors,omitempty"`
	EvidenceIDs         []EvidenceID `json:"evidence_ids,omitempty"`
}

type NegativeVerificationStatus string

const (
	NegativeVerified          NegativeVerificationStatus = "VERIFIED"
	NegativeInsufficientScope NegativeVerificationStatus = "INSUFFICIENT_SCOPE"
	NegativeContradicted      NegativeVerificationStatus = "CONTRADICTED"
)

type NegativeVerification struct {
	Status      NegativeVerificationStatus `json:"status"`
	EvidenceIDs []EvidenceID               `json:"evidence_ids,omitempty"`
	Notes       string                     `json:"notes,omitempty"`
	Limitations []string                   `json:"limitations,omitempty"`
}

type HypothesisID string

type HypothesisStatus string

const (
	HypothesisOpen       HypothesisStatus = "OPEN"
	HypothesisConfirmed  HypothesisStatus = "CONFIRMED"
	HypothesisRejected   HypothesisStatus = "REJECTED"
	HypothesisUnresolved HypothesisStatus = "UNRESOLVED"
)

type Hypothesis struct {
	ID               HypothesisID     `json:"id"`
	ConditionID      ConditionID      `json:"condition_id"`
	Statement        string           `json:"statement"`
	ExpectedEvidence []EvidenceKind   `json:"expected_evidence,omitempty"`
	Status           HypothesisStatus `json:"status"`
}

type Claim struct {
	ID                   ClaimID               `json:"id"`
	ConditionID          ConditionID           `json:"condition_id"`
	Result               ClaimResult           `json:"result"`
	EvidenceIDs          []EvidenceID          `json:"evidence_ids,omitempty"`
	Explanation          string                `json:"explanation,omitempty"`
	Limitations          []string              `json:"limitations,omitempty"`
	NegativeVerification *NegativeVerification `json:"negative_verification,omitempty"`
}

type EvidenceQuality string

const (
	QualityAuthoritative EvidenceQuality = "AUTHORITATIVE"
	QualityDeterministic EvidenceQuality = "DETERMINISTIC"
	QualityStructural    EvidenceQuality = "STRUCTURAL"
	QualityHeuristic     EvidenceQuality = "HEURISTIC"
	QualityLLMInferred   EvidenceQuality = "LLM_INFERRED"
)

type EvidenceKind string

const (
	EvidenceAdvisory       EvidenceKind = "ADVISORY"
	EvidenceFixDiff        EvidenceKind = "FIX_DIFF"
	EvidenceModuleGraph    EvidenceKind = "MODULE_GRAPH"
	EvidencePackageList    EvidenceKind = "PACKAGE_LIST"
	EvidenceGovulncheck    EvidenceKind = "GOVULNCHECK"
	EvidenceSourceSnippet  EvidenceKind = "SOURCE_SNIPPET"
	EvidenceCallPath       EvidenceKind = "CALL_PATH"
	EvidenceDataFlow       EvidenceKind = "DATA_FLOW"
	EvidenceEntrypoint     EvidenceKind = "ENTRYPOINT"
	EvidenceValidation     EvidenceKind = "VALIDATION"
	EvidenceConfiguration  EvidenceKind = "CONFIGURATION"
	EvidenceRuntime        EvidenceKind = "RUNTIME"
	EvidenceBuild          EvidenceKind = "BUILD"
	EvidenceTest           EvidenceKind = "TEST"
	EvidenceSearchResult   EvidenceKind = "SEARCH_RESULT"
	EvidenceToolLimitation EvidenceKind = "TOOL_LIMITATION"
)

type Evidence struct {
	ID           EvidenceID      `json:"id"`
	Kind         EvidenceKind    `json:"kind"`
	Quality      EvidenceQuality `json:"quality"`
	Source       string          `json:"source"`
	Repository   string          `json:"repository,omitempty"`
	Commit       string          `json:"commit,omitempty"`
	File         string          `json:"file,omitempty"`
	StartLine    int             `json:"start_line,omitempty"`
	EndLine      int             `json:"end_line,omitempty"`
	Tool         string          `json:"tool,omitempty"`
	ToolVersion  string          `json:"tool_version,omitempty"`
	Command      string          `json:"command,omitempty"`
	Content      string          `json:"content"`
	ArtifactHash string          `json:"artifact_hash,omitempty"`
	Limitations  []string        `json:"limitations,omitempty"`
}

type CallSite struct {
	File     string `json:"file"`
	Line     int    `json:"line,omitempty"`
	Column   int    `json:"column,omitempty"`
	Function string `json:"function"`
	Package  string `json:"package,omitempty"`
}

type CallPath struct {
	ConditionID ConditionID `json:"condition_id,omitempty"`
	EvidenceID  EvidenceID  `json:"evidence_id,omitempty"`
	Frames      []CallSite  `json:"frames"`
}

type DataFlow struct {
	ConditionID     ConditionID `json:"condition_id,omitempty"`
	Source          CallSite    `json:"source"`
	Origin          DataOrigin  `json:"origin"`
	Transformations []CallSite  `json:"transformations,omitempty"`
	Sink            CallSite    `json:"sink"`
	Summary         string      `json:"summary,omitempty"`
}

type Entrypoint struct {
	CallSite
	Kind    string `json:"kind,omitempty"`
	Exposed bool   `json:"exposed"`
}

type Validation struct {
	CallSite
	Property string `json:"property"`
}

type ConfigItem struct {
	Key      string     `json:"key"`
	Value    string     `json:"value"`
	Evidence EvidenceID `json:"evidence_id,omitempty"`
}

type EvidenceGraph struct {
	mu              sync.Mutex   `json:"-"`
	Version         string       `json:"version"`
	Evidence        []Evidence   `json:"evidence"`
	CallPaths       []CallPath   `json:"call_paths,omitempty"`
	DataFlows       []DataFlow   `json:"data_flows,omitempty"`
	Entrypoints     []Entrypoint `json:"entrypoints,omitempty"`
	Validations     []Validation `json:"validations,omitempty"`
	Configuration   []ConfigItem `json:"configuration,omitempty"`
	Runtime         []EvidenceID `json:"runtime,omitempty"`
	ToolLimitations []string     `json:"tool_limitations,omitempty"`
	Limitations     []string     `json:"limitations,omitempty"`
	Hash            string       `json:"hash,omitempty"`
}

// AddEvidence appends e to the graph, assigning an ID when empty, and
// returns the assigned EvidenceID. Safe for concurrent use — parallel
// condition evaluators add evidence into the same case graph.
func (g *EvidenceGraph) AddEvidence(e Evidence) EvidenceID {
	g.mu.Lock()
	defer g.mu.Unlock()
	if e.ID == "" {
		e.ID = EvidenceID(fmt.Sprintf("EV-%03d", len(g.Evidence)+1))
	}
	g.Evidence = append(g.Evidence, e)
	return e.ID
}

// AddLimitation appends a limitation, skipping exact duplicates — the
// same note (e.g. "no call sites") is meaningless when repeated per
// condition or per dynamic marker.
func (g *EvidenceGraph) AddLimitation(s string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, l := range g.Limitations {
		if l == s {
			return
		}
	}
	g.Limitations = append(g.Limitations, s)
}

func (g *EvidenceGraph) AddToolLimitation(s string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, l := range g.ToolLimitations {
		if l == s {
			return
		}
	}
	g.ToolLimitations = append(g.ToolLimitations, s)
}

func (g *EvidenceGraph) AddDataFlows(flows ...DataFlow) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.DataFlows = append(g.DataFlows, flows...)
}

func (g *EvidenceGraph) AddValidations(vals ...Validation) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.Validations = append(g.Validations, vals...)
}

func (g *EvidenceGraph) AddCallPath(cp CallPath) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.CallPaths = append(g.CallPaths, cp)
}

// EvidenceList returns a copy of the evidence slice for safe iteration
// while other goroutines may be appending.
func (g *EvidenceGraph) EvidenceList() []Evidence {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]Evidence, len(g.Evidence))
	copy(out, g.Evidence)
	return out
}

// ComputeHash sets Hash to the sha256 of the canonical graph encoding
// (Hash field excluded) and returns it.
func (g *EvidenceGraph) ComputeHash() string {
	g.Hash = ""
	b, err := json.Marshal(g)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	g.Hash = hex.EncodeToString(sum[:])
	return g.Hash
}

type ReviewResult string

const (
	ReviewAccept ReviewResult = "ACCEPT"
	ReviewRevise ReviewResult = "REVISE"
)

type ReviewFinding struct {
	TargetType    string `json:"target_type"`
	TargetID      string `json:"target_id"`
	Problem       string `json:"problem"`
	RequiredCheck string `json:"required_check,omitempty"`
	Severity      string `json:"severity,omitempty"`
}

type Review struct {
	ID       ReviewID        `json:"id"`
	Result   ReviewResult    `json:"result"`
	Findings []ReviewFinding `json:"findings,omitempty"`
}

type VerdictResult struct {
	Verdict      Verdict       `json:"verdict"`
	Reason       string        `json:"reason"`
	ConditionIDs []ConditionID `json:"condition_ids,omitempty"`
	EvidenceIDs  []EvidenceID  `json:"evidence_ids,omitempty"`
	Limitations  []string      `json:"limitations,omitempty"`
}

type AnalysisLimits struct {
	MaxIterations       int `json:"max_iterations"`
	MaxToolCalls        int `json:"max_tool_calls"`
	MaxLLMCalls         int `json:"max_llm_calls"`
	MaxSourceReads      int `json:"max_source_reads"`
	MaxReviewIterations int `json:"max_review_iterations"`
}

type AnalysisUsage struct {
	Iterations       int `json:"iterations"`
	ToolCalls        int `json:"tool_calls"`
	LLMCalls         int `json:"llm_calls"`
	SourceReads      int `json:"source_reads"`
	ReviewIterations int `json:"review_iterations"`
}

type WorkflowStatus struct {
	State         WorkflowState `json:"state"`
	PreviousState WorkflowState `json:"previous_state,omitempty"`
	Reason        string        `json:"reason,omitempty"`
	StartedAt     time.Time     `json:"started_at"`
	UpdatedAt     time.Time     `json:"updated_at"`
	FinishedAt    *time.Time    `json:"finished_at,omitempty"`
	Iteration     int           `json:"iteration"`
	// Timings records wall-clock seconds spent in each workflow state —
	// persisted so slow stages are visible in the case file, not guessed.
	Timings map[string]float64 `json:"timings,omitempty"`
	Limits  AnalysisLimits     `json:"limits"`
	Usage   AnalysisUsage      `json:"usage"`
}

type AnalysisCase struct {
	// mu guards Usage counters when condition evaluators or scan workers
	// touch the case concurrently. JSON ignores unexported fields.
	mu            sync.Mutex      `json:"-"`
	ID            CaseID          `json:"id"`
	Vulnerability Vulnerability   `json:"vulnerability"`
	Product       ProductSnapshot `json:"product"`
	Affected      *AffectedResult `json:"affected,omitempty"`
	RootCause     *RootCauseModel `json:"root_cause,omitempty"`
	Exploit       *ExploitModel   `json:"exploit_model,omitempty"`
	EvidenceGraph EvidenceGraph   `json:"evidence_graph"`
	Claims        []Claim         `json:"claims,omitempty"`
	Reviews       []Review        `json:"reviews,omitempty"`
	Verdict       *VerdictResult  `json:"verdict,omitempty"`
	Workflow      WorkflowStatus  `json:"workflow"`
}

// Usage counter helpers — the only safe writers under parallelism.
func (c *AnalysisCase) IncLLMCalls()    { c.mu.Lock(); c.Workflow.Usage.LLMCalls++; c.mu.Unlock() }
func (c *AnalysisCase) IncToolCalls()   { c.mu.Lock(); c.Workflow.Usage.ToolCalls++; c.mu.Unlock() }
func (c *AnalysisCase) IncSourceReads() { c.mu.Lock(); c.Workflow.Usage.SourceReads++; c.mu.Unlock() }
func (c *AnalysisCase) IncReviewIterations() {
	c.mu.Lock()
	c.Workflow.Usage.ReviewIterations++
	c.mu.Unlock()
}
func (c *AnalysisCase) UsageSnapshot() AnalysisUsage {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Workflow.Usage
}
