package exposure

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"example.com/vuln-analyzer/internal/domain"
)

// Deployment manifests declare exposure the source tree cannot express —
// including surfaces that belong to sibling services in the same bundle
// (a compose file publishing the AMQP broker is deployment context for a
// client-side parser vulnerability, not the product's own listener).
// Facts record what the manifest declares; whether a published surface
// fronts the analyzed process is a deployment question.
// a Service of type LoadBalancer, an Ingress/Route/Gateway, a published
// compose port or hostPort/hostNetwork all open surfaces beyond what the
// code's bind address says. ScanDeploy is a line-level scan — it reads
// kind/type/port markers without a YAML parser, so it survives Helm
// templates; templated values are flagged "template" rather than
// interpreted.
var (
	// deployDirRe scopes the scan to deployment-ish directories — config
	// YAML elsewhere (CI, tests) must not inflate the exposure surface.
	deployDirRe = regexp.MustCompile(`(?i)^(helm|deploy|deployments?|k8s|kubernetes|charts?|manifests?|openshift|istio|infra|docker|compose)$`)
	// deploySkipDirs never count as deployment scope — fixture trees.
	deploySkipDirs = map[string]bool{
		"vendor": true, ".git": true, "node_modules": true,
		"testdata": true, "test": true, "tests": true,
	}
	composeFileRe = regexp.MustCompile(`(?i)^(?:docker-)?compose[^/]*\.ya?ml$`)
	dockerfileRe  = regexp.MustCompile(`(?i)^Dockerfile[^/]*$`)
	kindRe        = regexp.MustCompile(`^\s*kind:\s*"?([A-Za-z]+)"?\s*$`)
	svcTypeRe     = regexp.MustCompile(`^\s*type:\s*"?([A-Za-z]+)"?\s*$`)
	hostRe        = regexp.MustCompile(`^\s*-?\s*host:\s*"?([^"'\s]+)"?\s*$`)
	hostPortRe    = regexp.MustCompile(`^\s*-?\s*hostPort:\s*(\d+)\s*$`)
	hostNetRe     = regexp.MustCompile(`^\s*hostNetwork:\s*true\s*$`)
	nodePortRe    = regexp.MustCompile(`^\s*-?\s*nodePort:\s*(\d+)\s*$`)
	publishRe     = regexp.MustCompile(`^\s*-\s*"?(\d+):(\d+)"?\s*$`) // compose "HOST:CONTAINER"
)

// ingressKinds are Kubernetes-adjacent objects that publish inbound
// traffic beyond a Service.
var ingressKinds = map[string]string{
	"Ingress":        "k8s:Ingress",
	"Route":          "openshift:Route",
	"Gateway":        "gateway-api:Gateway",
	"VirtualService": "istio:VirtualService",
	"IngressRoute":   "traefik:IngressRoute",
}

// ScanDeploy walks root for deployment manifests in deploy-scoped paths
// and returns one fact per published surface it can statically describe.
func ScanDeploy(root string) ([]domain.ExposureFact, error) {
	var out []domain.ExposureFact
	err := filepath.WalkDir(root, func(path string, e fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if e.IsDir() {
			if deploySkipDirs[e.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if !deployPath(root, path) {
			return nil
		}
		if info, err := e.Info(); err != nil || info.Size() > 1<<20 {
			return nil
		}
		facts, err := scanDeployFile(root, path)
		if err != nil {
			return nil
		}
		out = append(out, facts...)
		return nil
	})
	return out, err
}

// deployPath reports whether path lives under a deploy-scoped directory
// or is a compose/Dockerfile at any depth.
func deployPath(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	base := filepath.Base(rel)
	if composeFileRe.MatchString(base) || dockerfileRe.MatchString(base) {
		return true
	}
	if !strings.HasSuffix(strings.ToLower(base), ".yaml") &&
		!strings.HasSuffix(strings.ToLower(base), ".yml") {
		return false
	}
	for _, part := range strings.Split(filepath.Dir(rel), string(filepath.Separator)) {
		if deployDirRe.MatchString(part) {
			return true
		}
	}
	return false
}

func scanDeployFile(root, path string) ([]domain.ExposureFact, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	rel, _ := filepath.Rel(root, path)
	var out []domain.ExposureFact
	kind := ""
	line := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line++
		text := sc.Text()
		if m := kindRe.FindStringSubmatch(text); m != nil {
			kind = m[1]
			if t, ok := ingressKinds[kind]; ok {
				out = append(out, deployFact(t, "", rel, line))
			}
			continue
		}
		if m := hostPortRe.FindStringSubmatch(text); m != nil {
			out = append(out, deployFact("k8s:hostPort", "hostPort="+m[1], rel, line))
			continue
		}
		if hostNetRe.MatchString(text) {
			out = append(out, deployFact("k8s:hostNetwork", "hostNetwork=true", rel, line))
			continue
		}
		if kind == "Service" {
			if m := svcTypeRe.FindStringSubmatch(text); m != nil {
				switch m[1] {
				case "LoadBalancer", "NodePort", "ExternalName":
					out = append(out, deployFact("k8s:Service:"+m[1], m[1], rel, line))
				}
				continue
			}
			if m := nodePortRe.FindStringSubmatch(text); m != nil {
				out = append(out, deployFact("k8s:Service:NodePort", "nodePort="+m[1], rel, line))
			}
			continue
		}
		if m := hostRe.FindStringSubmatch(text); m != nil && kind != "" &&
			ingressKinds[kind] != "" && len(out) > 0 {
			last := &out[len(out)-1]
			if last.Address == "" {
				last.Address = m[1]
			}
		}
		// Compose published ports: "- \"HOST:CONTAINER\"" entries.
		if m := publishRe.FindStringSubmatch(text); m != nil &&
			composeFileRe.MatchString(filepath.Base(path)) {
			out = append(out, deployFact("compose:published-port",
				m[1]+":"+m[2], rel, line))
		}
	}
	return out, sc.Err()
}

func deployFact(target, addr, file string, line int) domain.ExposureFact {
	src := "manifest"
	if strings.Contains(addr, "{{") {
		addr = ""
		src = "template"
	}
	return domain.ExposureFact{
		CallSite:      domain.CallSite{File: file, Line: line},
		Direction:     "inbound",
		Kind:          "deployment",
		Target:        target,
		Address:       addr,
		AddressSource: src + " " + file,
		Scope:         domain.ScopeAllInterfaces,
	}
}
