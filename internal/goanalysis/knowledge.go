package goanalysis

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"

	"github.com/fedorovmv/izyan/internal/domain"
)

// Knowledge holds the ecosystem-semantics tables the provenance and
// exposure scanners consult: which calls produce which data origins,
// which calls merely pass a source's origin through, which names mark
// config decoding or credential attachment, and where listener
// primitives take their bind address. These are universal facts about
// Go ecosystem APIs — never product-specific identifiers.
//
// Entries extend without code changes through a KnowledgeFile
// (--knowledge). A missing entry degrades a trace to UNKNOWN (the safe
// direction); a wrong entry mislabels an origin (the dangerous one), so
// external files merge additively and a key already present is a
// conflict error, never a silent override.
type Knowledge struct {
	// SourceFuncs maps "pkgpath.Func" to the data origin its result
	// carries (os.Getenv → CONFIGURATION, net/http.Get → EXTERNAL).
	SourceFuncs map[string]domain.DataOrigin
	// PassthroughFuncs maps "pkgpath.Func" to the argument index whose
	// origin the call result carries (io.ReadAll → arg0).
	PassthroughFuncs map[string]int
	// ArgsMergeFuncs names "pkgpath.Func" combinators whose result merges
	// explicit argument provenance. The classifier still rejects callback
	// arguments and implicit formatter callbacks whose effects are unknown.
	ArgsMergeFuncs map[string]bool
	// PassthroughMethods names accessor methods whose result carries the
	// receiver's origin (scanner.Text(), buf.Bytes(), builder.String()).
	PassthroughMethods map[string]bool
	// SlicePopulateFuncs maps "pkgpath.Func" to (dst, src) argument
	// indexes: calls that fill a destination slice/writer from a source
	// (io.ReadFull(r, buf), binary.Read, io.Copy).
	SlicePopulateFuncs map[string][2]int
	// ReadIntoMethods names methods whose first argument is a destination
	// slice the receiver's bytes flow into (conn.Read(buf)).
	ReadIntoMethods map[string]bool
	// RecvMutateMethods names receiver-mutating calls that append/store
	// the argument's data into the receiver (buf.Write(x), b.ReadFrom(r)).
	RecvMutateMethods map[string]bool
	// PopulateNames names unmarshal/decode-family calls that fill an
	// out-parameter (&v) from a source: for methods the source is the
	// receiver (dec.Decode(&x)); for package funcs it is arg0
	// (json.Unmarshal(data, &x)).
	PopulateNames map[string]bool
	// ConfigTagKeys are struct tags whose fields are populated by
	// configuration decoding rather than request payloads.
	ConfigTagKeys []string
	// AuthCallNames names callees that attach credentials to a request or
	// client — evidence a peer is authenticated rather than anonymous.
	AuthCallNames map[string]bool
	// DBPkgs are exact package paths of data-store APIs; DBPkgHints are
	// import-path substrings (driver families span many module paths).
	DBPkgs     []string
	DBPkgHints []string
	// ServiceCallPkgHints are import-path substrings marking RPC
	// frameworks: a method whose receiver type's package imports one is
	// a service stub returning INTERNAL_SERVICE data.
	ServiceCallPkgHints []string
	// HTTPClientPkgs are package paths whose package-level request
	// functions and client methods get endpoint-aware origin refinement.
	HTTPClientPkgs map[string]bool
	// ListenerPrimitives are calls that make the product accept inbound
	// connections — a function containing one is a listener entrypoint.
	ListenerPrimitives []domain.SymbolRef
	// ListenAddrArg indexes the address argument per listener primitive
	// ("pkg.Symbol" → arg index); -1 when the address lives outside the
	// call (http.Server.Addr field, Serve(listener)).
	ListenAddrArg map[string]int
	// StringSemantics maps "pkgpath.Func" to a string-transform semantic
	// the dispatch-key evaluator computes deterministically:
	//   "identity_if_schemed" — result is arg0 verbatim when arg0 parses
	//     as a URL with a non-empty scheme (an `x::` forced prefix is
	//     allowed and preserved); otherwise the result is unknowable.
	//   "forced_split" — returns (forcedPrefix-or-"", rest) splitting
	//     arg0 on an `x::rest` marker.
	//   "subdir_split" — returns (base, subdir); base keeps the scheme.
	StringSemantics map[string]string
	// Sources records which files built this base ("name@data_version"),
	// in merge order — populated by Merge, not part of the JSON schema.
	Sources []string
}

// knowledge.json is the built-in ecosystem knowledge base — the same
// KnowledgeFile schema --knowledge accepts. It is data, not code: edit
// the file to change defaults, embed keeps the binary self-contained,
// and `analyzer knowledge` dumps it as the starting point for a custom
// extension file.
//
//go:embed knowledge.json
var defaultKnowledgeJSON []byte

// DefaultKnowledge returns a fresh copy of the built-in ecosystem
// tables parsed from the embedded knowledge.json. Safe to mutate
// (e.g. Merge) — each call builds new maps and slices.
func DefaultKnowledge() *Knowledge {
	f, err := parseKnowledgeFile(bytes.NewReader(defaultKnowledgeJSON))
	if err != nil {
		panic(fmt.Sprintf("embedded knowledge.json: %v", err))
	}
	kb := &Knowledge{}
	if err := kb.Merge(f); err != nil {
		panic(fmt.Sprintf("embedded knowledge.json: %v", err))
	}
	return kb
}

// AsFile renders the knowledge base in the extension-file schema —
// what `analyzer knowledge` prints and what a --knowledge file looks
// like.
func (k *Knowledge) AsFile() KnowledgeFile {
	return KnowledgeFile{
		SchemaVersion:       KnowledgeSchemaVersion,
		Language:            knowledgeLanguage,
		SourceFuncs:         originStrings(k.SourceFuncs),
		PassthroughFuncs:    k.PassthroughFuncs,
		ArgsMergeFuncs:      k.ArgsMergeFuncs,
		PassthroughMethods:  k.PassthroughMethods,
		SlicePopulateFuncs:  k.SlicePopulateFuncs,
		ReadIntoMethods:     k.ReadIntoMethods,
		RecvMutateMethods:   k.RecvMutateMethods,
		PopulateNames:       k.PopulateNames,
		ConfigTagKeys:       k.ConfigTagKeys,
		AuthCallNames:       k.AuthCallNames,
		DBPkgs:              k.DBPkgs,
		DBPkgHints:          k.DBPkgHints,
		ServiceCallPkgHints: k.ServiceCallPkgHints,
		HTTPClientPkgs:      k.HTTPClientPkgs,
		ListenerPrimitives:  k.ListenerPrimitives,
		ListenAddrArg:       k.ListenAddrArg,
		StringSemantics:     k.StringSemantics,
	}
}

// kb returns the configured knowledge base, installing the default when
// the index was built without one. Callers hold ix.mu.
func (ix *Index) kb() *Knowledge {
	if ix.KB == nil {
		ix.KB = DefaultKnowledge()
	}
	return ix.KB
}

// Knowledge returns the index's effective knowledge base, installing
// the defaults on first use — for reporting which sources/digest an
// analysis ran against.
func (ix *Index) Knowledge() *Knowledge {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	return ix.kb()
}

// KnowledgeSchemaVersion is the schema level this build writes and the
// newest it accepts: files without schema_version read as v1, files
// above it fail to load rather than misparse a schema they predate.
// Bump it when the format changes (e.g. new top-level sections like
// v2's string_semantics, v3's args_merge_funcs, per-language sections
// for non-Go analyzers).
const KnowledgeSchemaVersion = 3

// knowledgeLanguage tags files for this analyzer family — a file
// declaring another language is rejected instead of merging keys the
// Go analyzers will never look up.
const knowledgeLanguage = "go"

// KnowledgeFile is the JSON schema of a --knowledge extension file. Every
// field mirrors the same-named Knowledge field; files only add entries,
// never replace them.
type KnowledgeFile struct {
	// SchemaVersion is the file format level — absent means v1.
	SchemaVersion int `json:"schema_version,omitempty"`
	// Language names the analyzer family the file targets ("go").
	// Absent reads as this analyzer's language for compatibility.
	Language string `json:"language,omitempty"`
	// Name and Labels are informational provenance tags — e.g. the
	// embedded defaults declare name=builtin, labels=[builtin,upstream];
	// an org overlay might use labels=[corp]. They do not affect merge
	// semantics.
	Name   string   `json:"name,omitempty"`
	Labels []string `json:"labels,omitempty"`
	// DataVersion marks the revision of the table data itself — bump it
	// (a date works) when entries change. Recorded into Knowledge.Sources
	// so reports cite the exact data revision they ran against.
	DataVersion         string             `json:"data_version,omitempty"`
	SourceFuncs         map[string]string  `json:"source_funcs"`
	PassthroughFuncs    map[string]int     `json:"passthrough_funcs"`
	ArgsMergeFuncs      map[string]bool    `json:"args_merge_funcs"`
	PassthroughMethods  map[string]bool    `json:"passthrough_methods"`
	SlicePopulateFuncs  map[string][2]int  `json:"slice_populate_funcs"`
	ReadIntoMethods     map[string]bool    `json:"read_into_methods"`
	RecvMutateMethods   map[string]bool    `json:"recv_mutate_methods"`
	PopulateNames       map[string]bool    `json:"populate_names"`
	ConfigTagKeys       []string           `json:"config_tag_keys"`
	AuthCallNames       map[string]bool    `json:"auth_call_names"`
	DBPkgs              []string           `json:"db_pkgs"`
	DBPkgHints          []string           `json:"db_pkg_hints"`
	ServiceCallPkgHints []string           `json:"service_call_pkg_hints"`
	HTTPClientPkgs      map[string]bool    `json:"http_client_pkgs"`
	ListenerPrimitives  []domain.SymbolRef `json:"listener_primitives"`
	ListenAddrArg       map[string]int     `json:"listen_addr_arg"`
	StringSemantics     map[string]string  `json:"string_semantics"`
}

// LoadKnowledgeFile reads and validates a knowledge-extension JSON file.
// Unknown keys, malformed values (unrecognized origins, out-of-range
// indexes, `false` set members) are errors — a silently skipped entry
// would pretend coverage it does not add.
func LoadKnowledgeFile(path string) (KnowledgeFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return KnowledgeFile{}, err
	}
	f, err := parseKnowledgeFile(bytes.NewReader(b))
	if err != nil {
		return f, fmt.Errorf("%s: %w", path, err)
	}
	return f, nil
}

func parseKnowledgeFile(r io.Reader) (KnowledgeFile, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return KnowledgeFile{}, err
	}
	// Schema version and language are checked before the strict decode:
	// a file written for a newer schema or another analyzer must report
	// that, not a misleading "unknown field".
	var head struct {
		SchemaVersion int    `json:"schema_version"`
		Language      string `json:"language"`
	}
	if err := json.Unmarshal(b, &head); err != nil {
		return KnowledgeFile{}, err
	}
	if head.SchemaVersion < 0 || head.SchemaVersion > KnowledgeSchemaVersion {
		return KnowledgeFile{}, fmt.Errorf(
			"unsupported knowledge schema version %d (this build accepts up to %d)",
			head.SchemaVersion, KnowledgeSchemaVersion)
	}
	if head.Language != "" && head.Language != knowledgeLanguage {
		return KnowledgeFile{}, fmt.Errorf(
			"knowledge file targets language %q; this build analyzes %s",
			head.Language, knowledgeLanguage)
	}
	var f KnowledgeFile
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return f, err
	}
	return f, f.validate()
}

func (f KnowledgeFile) validate() error {
	for k, v := range f.SourceFuncs {
		if !validOrigin(v) {
			return fmt.Errorf("source_funcs[%q]: unknown data origin %q", k, v)
		}
	}
	for k, v := range f.PassthroughFuncs {
		if v < 0 {
			return fmt.Errorf("passthrough_funcs[%q]: negative arg index %d", k, v)
		}
	}
	for k, v := range f.SlicePopulateFuncs {
		if v[0] < 0 || v[1] < 0 {
			return fmt.Errorf("slice_populate_funcs[%q]: negative arg indexes %v", k, v)
		}
	}
	for k, v := range f.ListenAddrArg {
		if v < -1 {
			return fmt.Errorf("listen_addr_arg[%q]: arg index %d below -1", k, v)
		}
	}
	for k, v := range f.StringSemantics {
		switch v {
		case "identity_if_schemed", "forced_split", "subdir_split":
		default:
			return fmt.Errorf("string_semantics[%q]: unknown semantic %q", k, v)
		}
	}
	for field, m := range map[string]map[string]bool{
		"args_merge_funcs":    f.ArgsMergeFuncs,
		"passthrough_methods": f.PassthroughMethods,
		"read_into_methods":   f.ReadIntoMethods,
		"recv_mutate_methods": f.RecvMutateMethods,
		"populate_names":      f.PopulateNames,
		"auth_call_names":     f.AuthCallNames,
		"http_client_pkgs":    f.HTTPClientPkgs,
	} {
		for k, v := range m {
			if !v {
				return fmt.Errorf("%s[%q]: set members must be true (remove the entry instead)", field, k)
			}
		}
	}
	for i, p := range f.ListenerPrimitives {
		if p.Package == "" || p.Symbol == "" {
			return fmt.Errorf("listener_primitives[%d]: package and symbol are required", i)
		}
	}
	return nil
}

func validOrigin(o string) bool {
	switch domain.DataOrigin(o) {
	case domain.OriginExternalUntrusted, domain.OriginExternalAuthenticated,
		domain.OriginConfiguration, domain.OriginDatabase,
		domain.OriginInternalService, domain.OriginConstant,
		domain.OriginGenerated, domain.OriginUnknown:
		return true
	}
	return false
}

// Merge additively merges a validated KnowledgeFile into k. Repeating an
// entry with its existing value is a no-op — a file built on top of
// `analyzer knowledge` output stays valid. Repeating it with a
// different value aborts the merge: explicit edits beat silent
// overrides, so a file may add knowledge but never rewrite it.
func (k *Knowledge) Merge(f KnowledgeFile) error {
	k.init()
	if src := f.sourceDescriptor(); src != "" && !slices.Contains(k.Sources, src) {
		k.Sources = append(k.Sources, src)
	}
	join := func(field string, errs []error) error {
		if len(errs) > 0 {
			return fmt.Errorf("%s: %w", field, errs[0])
		}
		return nil
	}
	if err := join("source_funcs", mergeMap(k.SourceFuncs, stringMapOrigins(f.SourceFuncs))); err != nil {
		return err
	}
	if err := join("passthrough_funcs", mergeMap(k.PassthroughFuncs, f.PassthroughFuncs)); err != nil {
		return err
	}
	if err := join("args_merge_funcs", mergeMap(k.ArgsMergeFuncs, f.ArgsMergeFuncs)); err != nil {
		return err
	}
	if err := join("slice_populate_funcs", mergeMap(k.SlicePopulateFuncs, f.SlicePopulateFuncs)); err != nil {
		return err
	}
	if err := join("listen_addr_arg", mergeMap(k.ListenAddrArg, f.ListenAddrArg)); err != nil {
		return err
	}
	if err := join("string_semantics", mergeMap(k.StringSemantics, f.StringSemantics)); err != nil {
		return err
	}
	for field, pair := range map[string][2]map[string]bool{
		"passthrough_methods": {k.PassthroughMethods, f.PassthroughMethods},
		"read_into_methods":   {k.ReadIntoMethods, f.ReadIntoMethods},
		"recv_mutate_methods": {k.RecvMutateMethods, f.RecvMutateMethods},
		"populate_names":      {k.PopulateNames, f.PopulateNames},
		"auth_call_names":     {k.AuthCallNames, f.AuthCallNames},
		"http_client_pkgs":    {k.HTTPClientPkgs, f.HTTPClientPkgs},
	} {
		if err := join(field, mergeMap(pair[0], pair[1])); err != nil {
			return err
		}
	}
	for _, pair := range []struct {
		dst *[]string
		src []string
	}{
		{&k.ConfigTagKeys, f.ConfigTagKeys},
		{&k.DBPkgs, f.DBPkgs},
		{&k.DBPkgHints, f.DBPkgHints},
		{&k.ServiceCallPkgHints, f.ServiceCallPkgHints},
	} {
		for _, v := range pair.src {
			if !slices.Contains(*pair.dst, v) {
				*pair.dst = append(*pair.dst, v)
			}
		}
	}
	for _, p := range f.ListenerPrimitives {
		if slices.Contains(k.ListenerPrimitives, p) {
			continue
		}
		k.ListenerPrimitives = append(k.ListenerPrimitives, p)
	}
	return nil
}

// sourceDescriptor identifies a file for Knowledge.Sources — "name@data_version"
// when both are declared, whichever is present otherwise.
func (f KnowledgeFile) sourceDescriptor() string {
	switch {
	case f.Name != "" && f.DataVersion != "":
		return f.Name + "@" + f.DataVersion
	case f.Name != "":
		return f.Name
	default:
		return f.DataVersion
	}
}

// Digest is a content hash of the effective tables — the canonical
// file-schema rendering hashed with SHA-256. Reports cite it so a
// verdict is verifiable against a concrete knowledge content, not just
// a version label.
func (k *Knowledge) Digest() string {
	b, err := json.Marshal(k.AsFile())
	if err != nil {
		return "sha256:unmarshalable"
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// init allocates nil maps so Merge works on a zero-value Knowledge too.
func (k *Knowledge) init() {
	if k.SourceFuncs == nil {
		k.SourceFuncs = map[string]domain.DataOrigin{}
	}
	if k.PassthroughFuncs == nil {
		k.PassthroughFuncs = map[string]int{}
	}
	if k.ArgsMergeFuncs == nil {
		k.ArgsMergeFuncs = map[string]bool{}
	}
	if k.SlicePopulateFuncs == nil {
		k.SlicePopulateFuncs = map[string][2]int{}
	}
	if k.ListenAddrArg == nil {
		k.ListenAddrArg = map[string]int{}
	}
	if k.StringSemantics == nil {
		k.StringSemantics = map[string]string{}
	}
	for _, m := range []*map[string]bool{
		&k.PassthroughMethods, &k.ReadIntoMethods, &k.RecvMutateMethods,
		&k.PopulateNames, &k.AuthCallNames, &k.HTTPClientPkgs,
	} {
		if *m == nil {
			*m = map[string]bool{}
		}
	}
}

func originStrings(m map[string]domain.DataOrigin) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = string(v)
	}
	return out
}

func stringMapOrigins(m map[string]string) map[string]domain.DataOrigin {
	out := make(map[string]domain.DataOrigin, len(m))
	for k, v := range m {
		out[k] = domain.DataOrigin(v)
	}
	return out
}

// mergeMap applies src into dst: same-value repeats are no-ops, a key
// defined with a different value is a conflict — the caller reports the
// first error.
func mergeMap[V comparable](dst map[string]V, src map[string]V) []error {
	var errs []error
	for key, v := range src {
		if old, ok := dst[key]; ok {
			if old != v {
				errs = append(errs, fmt.Errorf("entry %q already defined (%v), refusing to override with %v", key, old, v))
			}
			continue
		}
		dst[key] = v
	}
	return errs
}
