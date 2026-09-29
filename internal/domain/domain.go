package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
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
	StateGapAnalysis          WorkflowState = "GAP_ANALYSIS"
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
	// AffectedModules carries per-affected-entry data for advisories that
	// span several modules (e.g. stdlib + golang.org/x/sys mirrors of the
	// same fix). Each entry holds the module path with its own version
	// ranges, packages and symbols; the resolver picks the entry matching
	// the product's dependency graph and narrows the vulnerability to it.
	AffectedModules []AffectedModule  `json:"affected_modules,omitempty"`
	Summary         string            `json:"summary,omitempty"`
	Description     string            `json:"description,omitempty"`
	CWE             []string          `json:"cwe,omitempty"`
	Modified        string            `json:"modified,omitempty"`
	References      []Reference       `json:"references,omitempty"`
	Provenance      map[string]string `json:"provenance,omitempty"`
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
	GoModDirective    string             `json:"go_mod_directive,omitempty"`
	ReleaseGoVersion  string             `json:"release_go_version,omitempty"`
	BinaryPath        string             `json:"binary_path,omitempty"`
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
	// SelectedModule is the affected-entry module the product was
	// resolved against (multi-module advisories carry alternatives —
	// e.g. stdlib + golang.org/x/sys — and only the entry matching the
	// product's dependency graph is authoritative).
	SelectedModule string `json:"selected_module,omitempty"`
	// CheckedModules names every advisory module entry probed against the
	// product's module graph — ModulePresent=FALSE means none of these
	// resolved to a product dependency.
	CheckedModules []string `json:"checked_modules,omitempty"`
	// CheckedPackages names the affected package paths probed against the
	// product's transitive import closure (go list -deps -test ./...,
	// including build-constraint-excluded files). PackagePresent=FALSE
	// means every listed path is absent — the code is not linked into
	// the product — not "some package was missing".
	CheckedPackages []string `json:"checked_packages,omitempty"`
}

// AffectedModule is one OSV affected[] entry: a module path with its own
// version ranges, packages and symbols. Advisories may list alternatives
// (stdlib + vendored module) — each is evaluated independently.
type AffectedModule struct {
	Module           string            `json:"module"`
	AffectedVersions []VersionRange    `json:"affected_versions,omitempty"`
	FixedVersions    []string          `json:"fixed_versions,omitempty"`
	AffectedPackages []AffectedPackage `json:"affected_packages,omitempty"`
	AffectedSymbols  []SymbolRef       `json:"affected_symbols,omitempty"`
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

// Condition param keys — declarative hints emitted by exploit patterns and
// consumed by evaluators. Unknown params are ignored, so patterns stay
// declarative: a param never asserts a verdict, it only narrows what to
// check.
const (
	// ParamInputSource declares where the condition's input is expected to
	// come from: "peer" (remote peer of a listener/dialed service), "arg"
	// (a product-code call argument) or "config" (deployment config).
	ParamInputSource = "input_source"
	// ParamDirection selects the reachability direction: "read" looks for
	// readers of the subject (data exposure), not paths to a sink.
	ParamDirection = "direction"
	// ParamSequence names an API pair ("a->b") the product must invoke for
	// the vulnerable round-trip to exist.
	ParamSequence = "sequence"
	// ParamBound carries a constraint expression (e.g. "length > INT32_MAX")
	// for INPUT_CONSTRAINT conditions; a text annotation until guard
	// semantics land.
	ParamBound = "bound"
	// ParamCheck selects a structural check: "symbol_present" verifies the
	// subject exists in the dependency source; "exposure" resolves the
	// network exposure of the vulnerable surface; "config_flag" /
	// "config_key" resolve a configuration knob's effective value.
	ParamCheck = "check"
	// ParamConfigPackage/ParamConfigSymbol name a code-level configuration
	// knob (e.g. crypto/tls + Config.InsecureSkipVerify) for
	// check=config_flag.
	ParamConfigPackage = "config_package"
	ParamConfigSymbol  = "config_symbol"
	// ParamConfigKey names a repository config-file key for
	// check=config_key.
	ParamConfigKey = "config_key"
	// ParamInsecure is the knob value that enables the vulnerable
	// configuration (default "true").
	ParamInsecure = "insecure_value"
)

const (
	InputPeer   = "peer"
	InputArg    = "arg"
	InputConfig = "config"

	DirectionRead = "read"

	CheckSymbolPresent = "symbol_present"
	CheckExposure      = "exposure"
	CheckConfigFlag    = "config_flag"
	CheckConfigKey     = "config_key"
	// CheckReachable routes a CUSTOM condition to the symbol-reachability
	// machinery (subjects, direction=read, sequence=a->b all apply).
	CheckReachable = "reachable"
)

// Exposure scope values — deterministic classification of a resolved
// address. Inbound: how broadly a listener binds; outbound: where the
// endpoint's value originates.
const (
	ScopeAllInterfaces = "all-interfaces"  // :port, 0.0.0.0, [::]
	ScopeLoopback      = "loopback"        // 127.0.0.1, ::1, localhost
	ScopeUnix          = "unix"            // unix socket path / "unix" network
	ScopeHostSpecific  = "host-specific"   // bound to a concrete IP/DNS name
	ScopeStatic        = "static-endpoint" // outbound literal/const address
	ScopeConfigured    = "configured"      // outbound address from env/config/var
	ScopeUnknown       = "unknown"
)

// ExposureFact is a resolved network-exposure fact: an inbound listener
// bind or an outbound endpoint into the vulnerable module. It is
// evidence, not a verdict — scope describes the fact, the caller decides
// what it means for exploitation.
type ExposureFact struct {
	CallSite
	// Direction: "inbound" (we listen) or "outbound" (we dial/connect).
	Direction string `json:"direction"`
	// Kind: "listener", "dial" or "endpoint-config".
	Kind string `json:"kind"`
	// Target is the callee that creates the exposure ("net.Listen",
	// "amqp091-go.DialTLS").
	Target string `json:"target,omitempty"`
	// Address is the resolved value when statically determinable.
	Address string `json:"address,omitempty"`
	// AddressSource records where Address came from: "literal", "const",
	// "var", "env:NAME", "config:key", "field:…" or "" when unresolved.
	AddressSource string `json:"address_source,omitempty"`
	Scope         string `json:"scope,omitempty"`
}

type Condition struct {
	ID                ConditionID       `json:"id"`
	Kind              ConditionKind     `json:"kind"`
	Description       string            `json:"description"`
	Mandatory         bool              `json:"mandatory"`
	Subject           *SymbolRef        `json:"subject,omitempty"`
	Subjects          []SymbolRef       `json:"subjects,omitempty"` // alternative symbols: condition holds if ANY is satisfied
	ArgIndex          int               `json:"arg_index,omitempty"`
	Params            map[string]string `json:"params,omitempty"`
	VerificationHints []string          `json:"verification_hints,omitempty"`
}

type ExploitModel struct {
	// Class is the inferred vulnerability class (INFO_LEAK, URI_CONFUSION,
	// ...) that selected the exploit pattern; "UNKNOWN" for the generic
	// fallback model.
	Class               string       `json:"class,omitempty"`
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
	// EvidenceIDs point at what the planner's action produced.
	EvidenceIDs []EvidenceID `json:"evidence_ids,omitempty"`
	// Notes record the action taken / why it stayed unresolved.
	Notes string `json:"notes,omitempty"`
}

type Claim struct {
	ID                   ClaimID               `json:"id"`
	ConditionID          ConditionID           `json:"condition_id"`
	Result               ClaimResult           `json:"result"`
	EvidenceIDs          []EvidenceID          `json:"evidence_ids,omitempty"`
	Explanation          string                `json:"explanation,omitempty"`
	Limitations          []string              `json:"limitations,omitempty"`
	NegativeVerification *NegativeVerification `json:"negative_verification,omitempty"`
	// Producer names the evaluator/agent that emitted the claim. Claims from
	// deterministic evaluators backed by deterministic evidence are immune
	// to reviewer demotion — reinterpretation cannot undo a verified fact.
	Producer string `json:"producer,omitempty"`
	// Falsifier marks how a FALSE claim was derived so negative verification
	// picks the matching strategy: "guards" = bound-guard coverage.
	Falsifier string `json:"falsifier,omitempty"`
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
	Receiver string `json:"receiver,omitempty"`
	Package  string `json:"package,omitempty"`
	// Callee names the invoked symbol (e.g. "amqp.DialTLS") when the site is
	// recorded for module-usage evidence rather than as an enclosing function.
	Callee string `json:"callee,omitempty"`
}

type CallPath struct {
	ConditionID ConditionID `json:"condition_id,omitempty"`
	EvidenceID  EvidenceID  `json:"evidence_id,omitempty"`
	Frames      []CallSite  `json:"frames"`
}

type DataFlow struct {
	ConditionID ConditionID `json:"condition_id,omitempty"`
	Source      CallSite    `json:"source"`
	// Arg is the sink call's argument index this flow was traced for;
	// -1 means the flow is not argument-scoped.
	Arg             int        `json:"arg"`
	Origin          DataOrigin `json:"origin"`
	Transformations []CallSite `json:"transformations,omitempty"`
	Sink            CallSite   `json:"sink"`
	Summary         string     `json:"summary,omitempty"`
	// Value is the argument's resolved integer literal/constant when the
	// trace could determine it — used to check constant arguments against
	// declared input bounds.
	Value *int64 `json:"value,omitempty"`
}

type Entrypoint struct {
	CallSite
	Kind    string `json:"kind,omitempty"`
	Detail  string `json:"detail,omitempty"`
	Exposed bool   `json:"exposed"`
}

type Validation struct {
	CallSite
	Property string `json:"property"`
	// Guard marks a terminating if-check on the argument. Origin-assignment
	// records (Guard=false) document where the value came from — they are
	// not guards and cannot cover a sink.
	Guard bool `json:"guard,omitempty"`
	// Conditional marks a guard nested inside control flow: it applies only
	// when the enclosing condition holds, so it cannot unconditionally
	// cover the sink.
	Conditional bool `json:"conditional,omitempty"`
	// Covers marks a guard found in a caller frame (a different file/line)
	// that constrains the argument reaching this sink. Nil for guards that
	// precede the sink call in its own frame.
	Covers *CallSite `json:"covers,omitempty"`
	// Arg is the sink-call argument index this record constrains;
	// -1 means it applies regardless of position.
	Arg int `json:"arg"`
	// BoundLow/BoundHigh record the inclusive range a sanitize guard
	// enforces on the value — resolved to integers when the guard's
	// comparison side is a literal or a named constant.
	BoundLow  *int64 `json:"bound_low,omitempty"`
	BoundHigh *int64 `json:"bound_high,omitempty"`
}

type ConfigItem struct {
	Key      string     `json:"key"`
	Value    string     `json:"value"`
	File     string     `json:"file,omitempty"`
	Line     int        `json:"line,omitempty"`
	Evidence EvidenceID `json:"evidence_id,omitempty"`
}

// ConfigAssignment is a product-code assignment to a configuration knob
// (a Type.Field subject): composite-literal keys and x.Field = value
// assignments, with the assigned value resolved to a literal/const when
// statically determinable.
type ConfigAssignment struct {
	CallSite
	// Subject is the knob key "pkg.Type.Field".
	Subject string `json:"subject"`
	Value   string `json:"value,omitempty"`
	// Source: "literal", "const", or "" when the value is not resolvable.
	Source string `json:"source,omitempty"`
}

type EvidenceGraph struct {
	mu           sync.Mutex   `json:"-"`
	Version      string       `json:"version"`
	Evidence     []Evidence   `json:"evidence"`
	CallPaths    []CallPath   `json:"call_paths,omitempty"`
	DataFlows    []DataFlow   `json:"data_flows,omitempty"`
	Entrypoints  []Entrypoint `json:"entrypoints,omitempty"`
	ModuleUsages []CallSite   `json:"module_usages,omitempty"`
	// ModuleReachable maps an affected symbol ("pkg.Symbol") to the
	// intra-module call chain (product-used API → ... → subject) proven by
	// vendored-source analysis.
	ModuleReachable map[string][]string `json:"module_reachable,omitempty"`
	// SymbolRefs maps a subject ("pkg.Symbol") to product-code reference
	// sites collected for read-direction conditions — the candidate
	// readers/writers of an exposed datum.
	SymbolRefs map[string][]CallSite `json:"symbol_refs,omitempty"`
	// SymbolDecls records deterministic presence checks of subjects in the
	// dependency source: key "pkg.Symbol" -> declaration site. A present
	// key with a nil site means "checked, not found"; an absent key means
	// the lookup never ran or failed.
	SymbolDecls map[string]*CallSite `json:"symbol_decls,omitempty"`
	// Exposures records resolved network-exposure facts: inbound listener
	// binds and outbound endpoints into the vulnerable module.
	Exposures []ExposureFact `json:"exposures,omitempty"`
	// ConfigFlags maps a knob key "pkg.Type.Field" to the assignments
	// product code makes to it — empty list under a present key means
	// "checked, no assignments".
	ConfigFlags map[string][]ConfigAssignment `json:"config_flags,omitempty"`
	// ConfigFieldKinds maps a knob key to the field's underlying kind
	// ("bool", "string", …) — enables Go zero-value reasoning when the
	// knob is never assigned.
	ConfigFieldKinds map[string]string `json:"config_field_kinds,omitempty"`
	Validations      []Validation      `json:"validations,omitempty"`
	Configuration    []ConfigItem      `json:"configuration,omitempty"`
	Runtime          []EvidenceID      `json:"runtime,omitempty"`
	// ToolExecutions is the audit trail of external tool invocations
	// (spec §22): which tool ran, with what arguments, exit code and
	// output hashes — so every claim can be traced to a concrete run.
	ToolExecutions  []ToolExecution `json:"tool_executions,omitempty"`
	ToolLimitations []string        `json:"tool_limitations,omitempty"`
	Limitations     []string        `json:"limitations,omitempty"`
	Hash            string          `json:"hash,omitempty"`
}

// ToolExecution is one external tool invocation (spec §22). Stdout/stderr
// are hashed rather than stored — large outputs (govulncheck -json) are
// already persisted as evidence content; the hash pins the record to it.
type ToolExecution struct {
	ID           string   `json:"id"`
	Tool         string   `json:"tool"`
	Version      string   `json:"version,omitempty"`
	Dir          string   `json:"dir,omitempty"`
	Args         []string `json:"args,omitempty"`
	ExitCode     int      `json:"exit_code"`
	StdoutSHA256 string   `json:"stdout_sha256,omitempty"`
	StderrSHA256 string   `json:"stderr_sha256,omitempty"`
	DurationMs   int64    `json:"duration_ms"`
	Error        string   `json:"error,omitempty"`
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

// EvidenceByID returns the evidence with the given id, or nil.
func (g *EvidenceGraph) EvidenceByID(id EvidenceID) *Evidence {
	g.mu.Lock()
	defer g.mu.Unlock()
	for i := range g.Evidence {
		if g.Evidence[i].ID == id {
			return &g.Evidence[i]
		}
	}
	return nil
}

// AddRuntimeEvidence records e as RUNTIME evidence and links its id into
// Runtime — the graph slice enumerating facts about the analyzed artifact's
// build/runtime environment (binary build info, target platform).
func (g *EvidenceGraph) AddRuntimeEvidence(e Evidence) EvidenceID {
	e.Kind = EvidenceRuntime
	id := g.AddEvidence(e)
	g.mu.Lock()
	g.Runtime = append(g.Runtime, id)
	g.mu.Unlock()
	return id
}

// AddToolExecution appends an audit record, assigning a TX-id.
func (g *EvidenceGraph) AddToolExecution(t ToolExecution) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if t.ID == "" {
		t.ID = fmt.Sprintf("TX-%03d", len(g.ToolExecutions)+1)
	}
	g.ToolExecutions = append(g.ToolExecutions, t)
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

// ReplaceDataFlow swaps the flow recorded for the same condition, sink
// position and argument index (the gap-analysis loop's deeper trace
// supersedes the shallower UNKNOWN one). Appends when nothing matches.
func (g *EvidenceGraph) ReplaceDataFlow(f DataFlow) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for i, ex := range g.DataFlows {
		if ex.ConditionID == f.ConditionID &&
			ex.Arg == f.Arg &&
			ex.Sink.File == f.Sink.File && ex.Sink.Line == f.Sink.Line {
			g.DataFlows[i] = f
			return
		}
	}
	g.DataFlows = append(g.DataFlows, f)
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

func (g *EvidenceGraph) AddModuleUsages(sites ...CallSite) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.ModuleUsages = append(g.ModuleUsages, sites...)
}

func (g *EvidenceGraph) AddModuleReachable(key string, chain []string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.ModuleReachable == nil {
		g.ModuleReachable = map[string][]string{}
	}
	g.ModuleReachable[key] = chain
}

func (g *EvidenceGraph) AddSymbolRefs(key string, sites ...CallSite) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.SymbolRefs == nil {
		g.SymbolRefs = map[string][]CallSite{}
	}
	g.SymbolRefs[key] = append(g.SymbolRefs[key], sites...)
}

// AddSymbolDecl records the outcome of a presence check: site nil means
// "checked, not found in the dependency source".
func (g *EvidenceGraph) AddSymbolDecl(key string, site *CallSite) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.SymbolDecls == nil {
		g.SymbolDecls = map[string]*CallSite{}
	}
	g.SymbolDecls[key] = site
}

// SymbolRefsFor returns the reference sites recorded for key (nil when the
// read-scope scan found none or never ran — disambiguated by the check
// evidence record).
func (g *EvidenceGraph) SymbolRefsFor(key string) []CallSite {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]CallSite, len(g.SymbolRefs[key]))
	copy(out, g.SymbolRefs[key])
	return out
}

// SymbolDeclFor reports the presence-check outcome for key: found=true,
// site non-nil when declared.
func (g *EvidenceGraph) SymbolDeclFor(key string) (site *CallSite, checked bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	site, checked = g.SymbolDecls[key]
	return site, checked
}

// AddConfigFlag records an assignment to a configuration knob; a nil
// assignment still records that the knob was checked.
func (g *EvidenceGraph) AddConfigFlag(subject string, a ...ConfigAssignment) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.ConfigFlags == nil {
		g.ConfigFlags = map[string][]ConfigAssignment{}
	}
	g.ConfigFlags[subject] = append(g.ConfigFlags[subject], a...)
}

// ConfigFlagsFor returns assignments recorded for the knob; checked
// reports whether the lookup ran at all.
func (g *EvidenceGraph) ConfigFlagsFor(subject string) (list []ConfigAssignment, checked bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	list, checked = g.ConfigFlags[subject]
	return list, checked
}

// AddConfigFieldKind records the underlying kind of a config knob field.
func (g *EvidenceGraph) AddConfigFieldKind(subject, kind string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.ConfigFieldKinds == nil {
		g.ConfigFieldKinds = map[string]string{}
	}
	g.ConfigFieldKinds[subject] = kind
}

// SymbolFieldKind returns the recorded field kind for the knob.
func (g *EvidenceGraph) SymbolFieldKind(subject string) (string, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	k, ok := g.ConfigFieldKinds[subject]
	return k, ok
}

// AddConfigItem records a configuration key/value found in the repo.
func (g *EvidenceGraph) AddConfigItem(it ConfigItem) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.Configuration = append(g.Configuration, it)
}

// ConfigItems returns recorded configuration items.
func (g *EvidenceGraph) ConfigItems() []ConfigItem {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]ConfigItem, len(g.Configuration))
	copy(out, g.Configuration)
	return out
}

// AddExposure records a resolved exposure fact.
func (g *EvidenceGraph) AddExposure(f ExposureFact) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.Exposures = append(g.Exposures, f)
}

// ExposuresList returns a copy of the recorded exposure facts.
func (g *EvidenceGraph) ExposuresList() []ExposureFact {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]ExposureFact, len(g.Exposures))
	copy(out, g.Exposures)
	return out
}

func (g *EvidenceGraph) AddEntrypoints(eps ...Entrypoint) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.Entrypoints = append(g.Entrypoints, eps...)
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
	Hypotheses    []Hypothesis    `json:"hypotheses,omitempty"`
	Reviews       []Review        `json:"reviews,omitempty"`
	Verdict       *VerdictResult  `json:"verdict,omitempty"`
	// GovulncheckCoverage: "" unknown | "covered" the advisory exists in the
	// govulncheck DB | "not_in_db" it was never evaluated — silence is not
	// evidence of no path.
	GovulncheckCoverage string `json:"govulncheck_coverage,omitempty"`
	// PriorCase references the previous stored run of the same
	// vulnerability/repository pair — the reproducibility-diff baseline.
	PriorCase CaseID         `json:"prior_case,omitempty"`
	Workflow  WorkflowStatus `json:"workflow"`
}

// AddHypothesis appends a hypothesis with an assigned H-id.
func (c *AnalysisCase) AddHypothesis(h Hypothesis) HypothesisID {
	c.mu.Lock()
	defer c.mu.Unlock()
	if h.ID == "" {
		h.ID = HypothesisID(fmt.Sprintf("H-%03d", len(c.Hypotheses)+1))
	}
	c.Hypotheses = append(c.Hypotheses, h)
	return h.ID
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

// securityTransformRe matches callee names that can alter whether exploit
// input still violates the sink's constraint — quoting, sanitization,
// bounds, crypto. A recorded transform is provenance, never proof: the
// analyzer does not model transform semantics, so a security-relevant
// transform is flagged for review, not trusted as a guard.
var securityTransformRe = regexp.MustCompile(`(?i)escape|quote|sanitiz|clean|valid|check|encrypt|decrypt|sign|verify|hash|md5|sha|limit|truncat|bound|cap|mask|redact|filter`)

// IsSecurityTransform reports whether a transformation callee name is
// security-relevant — it may change the properties an exploit condition
// depends on, so its presence is flagged in claim limitations.
func IsSecurityTransform(callee string) bool {
	base := callee
	if i := strings.LastIndex(base, "."); i >= 0 {
		base = base[i+1:]
	}
	return securityTransformRe.MatchString(base)
}
