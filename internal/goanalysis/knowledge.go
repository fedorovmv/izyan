package goanalysis

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"slices"

	"example.com/vuln-analyzer/internal/domain"
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
}

// DefaultKnowledge returns a fresh copy of the built-in ecosystem
// tables. Safe to mutate (e.g. Merge) — each call builds new maps.
func DefaultKnowledge() *Knowledge {
	return &Knowledge{
		SourceFuncs: map[string]domain.DataOrigin{
			"os.Getenv":               domain.OriginConfiguration,
			"os.ReadFile":             domain.OriginConfiguration,
			"io/ioutil.ReadFile":      domain.OriginConfiguration,
			"flag.String":             domain.OriginConfiguration,
			"flag.Int":                domain.OriginConfiguration,
			"flag.Bool":               domain.OriginConfiguration,
			"flag.Parse":              domain.OriginConfiguration,
			"fmt.Sscanf":              domain.OriginUnknown,
			"os.Open":                 domain.OriginConfiguration,
			"net/http.Get":            domain.OriginExternalUntrusted,
			"net/http.Post":           domain.OriginExternalUntrusted,
			"net/http.ReadRequest":    domain.OriginExternalUntrusted,
			"encoding/json.Unmarshal": domain.OriginUnknown,
		},
		PassthroughFuncs: map[string]int{
			"io.ReadAll":                     0,
			"io/ioutil.ReadAll":              0,
			"bufio.NewScanner":               0,
			"bufio.NewReader":                0,
			"bufio.NewReaderSize":            0,
			"bytes.NewReader":                0,
			"bytes.NewBuffer":                0,
			"bytes.NewBufferString":          0,
			"strings.NewReader":              0,
			"encoding/json.NewDecoder":       0,
			"encoding/xml.NewDecoder":        0,
			"net/http.NewRequest":            1, // (method, url, body)
			"net/http.NewRequestWithContext": 2, // (ctx, method, url, body)
			"net/url.Parse":                  0,
			"net/url.ParseQuery":             0,
		},
		PassthroughMethods: map[string]bool{
			"Text": true, "Bytes": true, "String": true,
		},
		SlicePopulateFuncs: map[string][2]int{
			"io.ReadFull":    {1, 0},
			"io.ReadAtLeast": {1, 0},
			"binary.Read":    {2, 0},
			"io.Copy":        {0, 1},
		},
		ReadIntoMethods: map[string]bool{
			"Read": true, "ReadAt": true,
		},
		RecvMutateMethods: map[string]bool{
			"Write": true, "WriteString": true, "WriteByte": true, "WriteRune": true,
			"ReadFrom": true,
		},
		PopulateNames: map[string]bool{
			"Unmarshal": true, "Decode": true, "DecodeElement": true,
			"UnmarshalExact": true, "DecodeValues": true, "Read": true,
		},
		ConfigTagKeys: []string{"mapstructure", "env", "envconfig", "toml", "ini"},
		AuthCallNames: map[string]bool{
			"SetBasicAuth": true, "BasicAuth": true, "SetAuth": true,
			"WithAuth": true, "WithCredentials": true, "WithPerRPCCredentials": true,
			"NewOauthAccess": true, "NewStaticTokenSource": true,
			"ReuseTokenSource": true, "SetToken": true,
		},
		DBPkgs: []string{"database/sql"},
		DBPkgHints: []string{
			"sqlx", "gorm", "pgx", "mongo", "redis", "etcd", "gocql",
			"elasticsearch",
		},
		ServiceCallPkgHints: []string{"google.golang.org/grpc"},
		HTTPClientPkgs:      map[string]bool{"net/http": true},
		ListenerPrimitives: []domain.SymbolRef{
			{Package: "net", Symbol: "Listen"},
			{Package: "net", Symbol: "ListenTCP"},
			{Package: "net", Symbol: "ListenUDP"},
			{Package: "net", Symbol: "Listener.Accept"},
			{Package: "net/http", Symbol: "ListenAndServe"},
			{Package: "net/http", Symbol: "ListenAndServeTLS"},
			{Package: "net/http", Symbol: "Server.Serve"},
			{Package: "net/http", Symbol: "Server.ListenAndServe"},
			{Package: "google.golang.org/grpc", Symbol: "NewServer"},
			{Package: "google.golang.org/grpc", Symbol: "Server.Serve"},
			{Package: "google.golang.org/grpc", Symbol: "Server.ServeHTTP"},
		},
		ListenAddrArg: map[string]int{
			"net.Listen":                              1,
			"net.ListenTCP":                           1,
			"net.ListenUDP":                           1,
			"net/http.ListenAndServe":                 0,
			"net/http.ListenAndServeTLS":              0,
			"net/http.Server.ListenAndServe":          -1,
			"net/http.Server.Serve":                   -1,
			"google.golang.org/grpc.NewServer":        -1,
			"google.golang.org/grpc.Server.Serve":     -1,
			"google.golang.org/grpc.Server.ServeHTTP": -1,
			"net.Listener.Accept":                     -1,
		},
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

// KnowledgeFile is the JSON schema of a --knowledge extension file. Every
// field mirrors the same-named Knowledge field; files only add entries,
// never replace them.
type KnowledgeFile struct {
	SourceFuncs         map[string]string  `json:"source_funcs"`
	PassthroughFuncs    map[string]int     `json:"passthrough_funcs"`
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
}

// LoadKnowledgeFile reads and validates a knowledge-extension JSON file.
// Unknown keys, malformed values (unrecognized origins, out-of-range
// indexes, `false` set members) are errors — a silently skipped entry
// would pretend coverage it does not add.
func LoadKnowledgeFile(path string) (KnowledgeFile, error) {
	var f KnowledgeFile
	b, err := os.ReadFile(path)
	if err != nil {
		return f, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return f, fmt.Errorf("%s: %w", path, err)
	}
	if err := f.validate(); err != nil {
		return f, fmt.Errorf("%s: %w", path, err)
	}
	return f, nil
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
	for field, m := range map[string]map[string]bool{
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

// Merge additively merges a validated KnowledgeFile into k. An entry
// already present aborts the merge with a conflict error — explicit
// edits beat silent overrides, so a file may only add knowledge.
func (k *Knowledge) Merge(f KnowledgeFile) error {
	k.init()
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
	if err := join("slice_populate_funcs", mergeMap(k.SlicePopulateFuncs, f.SlicePopulateFuncs)); err != nil {
		return err
	}
	if err := join("listen_addr_arg", mergeMap(k.ListenAddrArg, f.ListenAddrArg)); err != nil {
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
	for field, pair := range map[string]struct {
		dst *[]string
		src []string
	}{
		"config_tag_keys":        {&k.ConfigTagKeys, f.ConfigTagKeys},
		"db_pkgs":                {&k.DBPkgs, f.DBPkgs},
		"db_pkg_hints":           {&k.DBPkgHints, f.DBPkgHints},
		"service_call_pkg_hints": {&k.ServiceCallPkgHints, f.ServiceCallPkgHints},
	} {
		for _, v := range pair.src {
			if slices.Contains(*pair.dst, v) {
				return fmt.Errorf("%s: entry %q already defined", field, v)
			}
			*pair.dst = append(*pair.dst, v)
		}
	}
	for _, p := range f.ListenerPrimitives {
		if slices.Contains(k.ListenerPrimitives, p) {
			return fmt.Errorf("listener_primitives: entry %s.%s already defined", p.Package, p.Symbol)
		}
		k.ListenerPrimitives = append(k.ListenerPrimitives, p)
	}
	return nil
}

// init allocates nil maps so Merge works on a zero-value Knowledge too.
func (k *Knowledge) init() {
	if k.SourceFuncs == nil {
		k.SourceFuncs = map[string]domain.DataOrigin{}
	}
	if k.PassthroughFuncs == nil {
		k.PassthroughFuncs = map[string]int{}
	}
	if k.SlicePopulateFuncs == nil {
		k.SlicePopulateFuncs = map[string][2]int{}
	}
	if k.ListenAddrArg == nil {
		k.ListenAddrArg = map[string]int{}
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

func stringMapOrigins(m map[string]string) map[string]domain.DataOrigin {
	out := make(map[string]domain.DataOrigin, len(m))
	for k, v := range m {
		out[k] = domain.DataOrigin(v)
	}
	return out
}

// mergeMap applies src into dst, returning one error per conflicting
// key — the caller reports the first.
func mergeMap[V any](dst map[string]V, src map[string]V) []error {
	var errs []error
	for key, v := range src {
		if _, ok := dst[key]; ok {
			errs = append(errs, fmt.Errorf("entry %q already defined", key))
			continue
		}
		dst[key] = v
	}
	return errs
}
