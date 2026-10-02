package goanalysis

import (
	"context"
	"fmt"
	"go/build"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"

	"example.com/vuln-analyzer/internal/affected"
	"example.com/vuln-analyzer/internal/domain"
)

// verifyLocusAbsent re-checks the locus-package-absent falsifier against
// the persisted build-graph evidence: every locus subject's package must be
// absent from `go list -deps`. A locus package found linked contradicts the
// FALSE; missing or undecodable package-list evidence leaves the scope
// insufficient — a loading failure is never absence.
//
// Unlike the subject-escape checks this verification needs no source index:
// the falsifier's premise is the build graph itself, so package absence
// cannot be escaped by wrappers, callbacks or dynamic dispatch.
func (v Verifier) verifyLocusAbsent(c *domain.AnalysisCase, claim domain.Claim,
	cond domain.Condition) domain.Claim {

	subjects := append([]domain.SymbolRef{}, cond.Subjects...)
	if cond.Subject != nil {
		subjects = append(subjects, *cond.Subject)
	}
	nv := &domain.NegativeVerification{Status: domain.NegativeVerified}
	if len(subjects) == 0 {
		return setNeg(claim, &domain.NegativeVerification{
			Status: domain.NegativeInsufficientScope,
			Notes:  "в условии не указаны уязвимые функции",
		})
	}

	set, evID, err := packageImportSet(c)
	if err != nil {
		return setNeg(claim, &domain.NegativeVerification{
			Status:      domain.NegativeInsufficientScope,
			EvidenceIDs: append([]domain.EvidenceID(nil), claim.EvidenceIDs...),
			Notes:       err.Error(),
		})
	}
	nv.EvidenceIDs = append(nv.EvidenceIDs, evID)

	var present []string
	for _, s := range subjects {
		if set[s.Package] {
			present = append(present, s.Package)
		}
	}
	if len(present) > 0 {
		nv.Status = domain.NegativeContradicted
		nv.Notes = fmt.Sprintf(
			"пакеты с уязвимым кодом (%s) входят в граф сборки снапшота; "+
				"код дефекта включён в приложение, условие отсутствия пакетов не выполняется",
			strings.Join(present, ", "))
		return setNeg(claim, nv)
	}
	nv.Notes = fmt.Sprintf(
		"все пакеты с уязвимым кодом (%d) отсутствуют в графе сборки go list -deps", len(subjects))
	nv.Limitations = append(nv.Limitations,
		"отсутствие пакетов проверено для параметров сборки (GOOS/GOARCH/теги); в других конфигурациях они могут попасть в бинарник")

	// Coverage gap check: files excluded under the recorded build context
	// (other GOOS/GOARCH, build tags, cgo) may still import a locus package
	// — the product could be built in a configuration where the code links.
	// Absence in one context is not absence in the product.
	if gap := excludedBuildImports(c, subjects); gap != "" {
		nv.Status = domain.NegativeInsufficientScope
		nv.Notes += "; " + gap
		return setNeg(claim, nv)
	}

	if c.Exploit != nil && len(c.Exploit.NonLocusBasis) > 0 {
		var names []string
		for _, d := range c.Exploit.NonLocusBasis {
			names = append(names, d.Symbol.Package+"."+d.Symbol.Symbol)
		}
		nv.Limitations = append(nv.Limitations, fmt.Sprintf(
			"проверка уязвимости сужена экспертными решениями `non_locus` (ручное подтверждение, не автоматическое доказательство): %s",
			strings.Join(names, ", ")))
	}
	return setNeg(claim, nv)
}

// excludedBuildImports scans the product tree for Go source files that the
// recorded build context excludes (build tags, GOOS/GOARCH filename
// suffixes, cgo rules) but which import a locus package. Their presence
// means a different build configuration links code the package list never
// saw — the absence proof is then scoped to the recorded context only.
// Directories the go tool never builds (vendor, testdata, _/.-prefixed)
// are skipped: excluded files there can never join a product build.
func excludedBuildImports(c *domain.AnalysisCase, subjects []domain.SymbolRef) string {
	root := c.Product.Repository
	if root == "" {
		return ""
	}
	locusPkgs := map[string]bool{}
	for _, s := range subjects {
		locusPkgs[s.Package] = true
	}
	ctx := build.Default
	if c.Product.GOOS != "" {
		ctx.GOOS = c.Product.GOOS
	}
	if c.Product.GOARCH != "" {
		ctx.GOARCH = c.Product.GOARCH
	}
	ctx.BuildTags = append([]string(nil), c.Product.BuildTags...)
	ctx.CgoEnabled = c.Product.CGOEnabled

	var gaps []string
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			base := d.Name()
			if base == ".git" || base == "vendor" || base == "testdata" ||
				strings.HasPrefix(base, "_") || (strings.HasPrefix(base, ".") && path != root) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") || strings.HasSuffix(d.Name(), "_test.go") {
			// Test files never link into the product binary under any
			// configuration — an excluded test importing the package is
			// not a coverage gap for exploitation.
			return nil
		}
		dir := filepath.Dir(path)
		match, merr := ctx.MatchFile(dir, d.Name())
		if merr == nil && match {
			return nil // part of the recorded build — the package list covers it
		}
		f, perr := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if perr != nil {
			return nil // cannot compile in any configuration — links nothing
		}
		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if locusPkgs[p] {
				rel, rerr := filepath.Rel(root, path)
				if rerr != nil {
					rel = path
				}
				gaps = append(gaps, rel+"→"+p)
				break
			}
		}
		return nil
	})
	if len(gaps) == 0 {
		return ""
	}
	return fmt.Sprintf(
		"файлы продукта, не вошедшие в текущую конфигурацию сборки, импортируют пакеты с уязвимым кодом: %s — "+
			"при сборке с другими тегами или под другую ОС они могут попасть в бинарник",
		strings.Join(gaps, ", "))
}

// packageImportSet decodes the persisted `go list -deps -json` evidence into
// the set of import paths the snapshot links.
func packageImportSet(c *domain.AnalysisCase) (map[string]bool, domain.EvidenceID, error) {
	for _, e := range c.EvidenceGraph.EvidenceList() {
		if e.Kind != domain.EvidencePackageList {
			continue
		}
		set, err := affected.PackageImportPaths([]byte(e.Content))
		if err != nil {
			return nil, "", fmt.Errorf(
				"не удалось прочитать список пакетов %s: %w; отсутствие в графе сборки не проверено", e.ID, err)
		}
		return set, e.ID, nil
	}
	return nil, "", fmt.Errorf(
		"нет данных о составе сборки (go list -deps); отсутствие в графе сборки не проверено")
}

// verifyLocusFunctionUnreached verifies the locus-function-unreached falsifier:
// locus packages are linked into the build graph, but the defect functions in L
// are unreached. It verifies:
//  1. No call paths (govulncheck traces), module reachability chains, or module
//     usages reach any subject symbol in L.
//  2. For symbols in internal/ packages, product code does not import the internal
//     package directly (Go compiler restriction guarantees no direct external references).
//  3. If source index is available, product entry points and call sites do not invoke
//     the subject, and dynamic markers (reflection, interface dispatch, func values,
//     go:linkname) do not escape to the subject.
func (v Verifier) verifyLocusFunctionUnreached(ctx context.Context, c *domain.AnalysisCase, claim domain.Claim,
	cond domain.Condition) domain.Claim {

	subjects := append([]domain.SymbolRef{}, cond.Subjects...)
	if cond.Subject != nil {
		subjects = append(subjects, *cond.Subject)
	}
	if len(subjects) == 0 && c.Exploit != nil {
		subjects = append(subjects, c.Exploit.RootCauses...)
	}
	if len(subjects) == 0 && c.RootCause != nil {
		for _, rc := range c.RootCause.RootCauses {
			subjects = append(subjects, domain.SymbolRef{Package: rc.Package, Symbol: rc.Symbol})
		}
	}
	if len(subjects) == 0 {
		return setNeg(claim, &domain.NegativeVerification{
			Status: domain.NegativeInsufficientScope,
			Notes:  "в условии не указаны уязвимые функции",
		})
	}

	nv := &domain.NegativeVerification{
		Status:      domain.NegativeVerified,
		EvidenceIDs: append([]domain.EvidenceID(nil), claim.EvidenceIDs...),
	}

	// 1. EvidenceGraph check: CallPaths, ModuleReachable, ModuleUsages.
	for _, cp := range c.EvidenceGraph.CallPaths {
		for _, fr := range cp.Frames {
			for _, sym := range subjects {
				if frameMatches(fr, sym) {
					nv.Status = domain.NegativeContradicted
					nv.Notes = fmt.Sprintf("трасса вызовов достигает уязвимой функции %s.%s; FALSE опровергнут",
						sym.Package, sym.Symbol)
					if cp.EvidenceID != "" {
						nv.EvidenceIDs = append(nv.EvidenceIDs, cp.EvidenceID)
					}
					return setNeg(claim, nv)
				}
			}
		}
	}

	for _, subj := range subjects {
		want := subj.Package + "." + subj.Symbol
		if chain, ok := c.EvidenceGraph.ModuleReachable[want]; ok {
			nv.Status = domain.NegativeContradicted
			nv.Notes = fmt.Sprintf("уязвимая функция %s достижима через вызовы внутри модуля: %s; FALSE опровергнут",
				want, strings.Join(chain, " -> "))
			return setNeg(claim, nv)
		}
		for _, u := range c.EvidenceGraph.ModuleUsages {
			if u.Callee == want {
				nv.Status = domain.NegativeContradicted
				nv.Notes = fmt.Sprintf("продукт напрямую вызывает %s на %s:%d; FALSE опровергнут",
					want, u.File, u.Line)
				return setNeg(claim, nv)
			}
		}
	}

	// 2. Direct import check for internal/ packages in product code.
	repoDir := ""
	if v.Source != nil && v.Source.Dir != "" {
		repoDir = v.Source.Dir
	} else if c.Product.Repository != "" {
		repoDir = c.Product.Repository
	}

	hasSource := repoDir != "" && dirHasGoFiles(repoDir)
	productImports := map[string][]string{}
	var linknamePragmas []string
	if hasSource {
		productImports, linknamePragmas = scanProductSource(repoDir)
	}

	for _, subj := range subjects {
		isInternal := isInternalPkg(subj.Package)

		// Check if product code directly imports subj.Package.
		if files, imported := productImports[subj.Package]; imported {
			if isInternal {
				nv.Status = domain.NegativeContradicted
				nv.Notes = fmt.Sprintf("код продукта напрямую импортирует внутренний пакет %s (%s); FALSE опровергнут",
					subj.Package, strings.Join(files, ", "))
				return setNeg(claim, nv)
			}
		}

		// Check linkname pragmas found in product source.
		for _, text := range linknamePragmas {
			if strings.Contains(text, subj.Package) || linknameNames(text, subj) {
				nv.Status = domain.NegativeContradicted
				nv.Notes = fmt.Sprintf("символ %s переопределен через go:linkname (%s)",
					subj.Package+"."+subj.Symbol, text)
				return setNeg(claim, nv)
			}
		}

		// 3. Source index checks if available.
		if v.Source != nil && hasSource {
			// Search for product references / call sites.
			sites, err := v.Source.SearchSymbol(ctx, subj)
			if err != nil {
				// If symbol search fails on non-internal symbol, scope is insufficient.
				if !isInternal {
					nv.Status = domain.NegativeInsufficientScope
					nv.Notes = "symbol search failed: " + err.Error()
					return setNeg(claim, nv)
				}
			} else if len(sites) > 0 {
				nv.Status = domain.NegativeContradicted
				nv.Notes = fmt.Sprintf("найдено %d вызовов/ссылок на %s.%s в коде продукта; FALSE опровергнут",
					len(sites), subj.Package, subj.Symbol)
				return setNeg(claim, nv)
			}

			// Dynamic markers (func_value, linkname, reflect, plugin).
			markers, merr := v.Source.ScanDynamic(ctx, subj)
			if merr != nil {
				if !isInternal {
					nv.Status = domain.NegativeInsufficientScope
					nv.Notes = "dynamic scan failed: " + merr.Error()
					return setNeg(claim, nv)
				}
			} else {
				for _, m := range markers {
					switch m.Kind {
					case "func_value":
						nv.Status = domain.NegativeContradicted
						nv.Notes = fmt.Sprintf("символ %s передан как значение функции (%s:%d); возможен косвенный вызов",
							subj.Package+"."+subj.Symbol, m.File, m.Line)
						return setNeg(claim, nv)
					case "linkname":
						if strings.Contains(m.Detail, subj.Package) || linknameNames(m.Detail, subj) {
							nv.Status = domain.NegativeContradicted
							nv.Notes = fmt.Sprintf("символ %s переопределен через go:linkname (%s:%d)",
								subj.Package+"."+subj.Symbol, m.File, m.Line)
							return setNeg(claim, nv)
						}
					case "reflect_method":
						if symbolIsMethod(subj) && symbolExported(subj) {
							nv.Limitations = append(nv.Limitations,
								"динамический вызов методов через reflect используется в продукте")
						}
					}
				}
			}

			// Interface dispatch sites.
			disp, derr := v.Source.InterfaceDispatchSites(ctx, subj)
			if derr == nil && len(disp) > 0 {
				nv.Status = domain.NegativeInsufficientScope
				nv.Notes = fmt.Sprintf("%d вызов(ов) через интерфейс могут вызывать %s.%s; конкретная реализация не определена",
					len(disp), subj.Package, subj.Symbol)
				return setNeg(claim, nv)
			}

			// Build-tag excluded files.
			gated, gerr := v.Source.GatedRefs(ctx, subj)
			if gerr == nil && len(gated) > 0 {
				nv.Status = domain.NegativeInsufficientScope
				nv.Notes = fmt.Sprintf("%d ссылок на %s.%s в файлах, исключенных тегами сборки",
					len(gated), subj.Package, subj.Symbol)
				return setNeg(claim, nv)
			}
		} else if !isInternal {
			// Non-internal subject without source index: cannot verify absent product calls.
			nv.Status = domain.NegativeInsufficientScope
			nv.Notes = fmt.Sprintf("индекс исходного кода недоступен для проверки не-internal функции %s.%s",
				subj.Package, subj.Symbol)
			return setNeg(claim, nv)
		}
	}

	nv.Notes = fmt.Sprintf("все функции дефектного локуса (%d) проверены: трассы вызовов отсутствуют, прямые ссылки и динамические утечки не обнаружены", len(subjects))
	if c.Exploit != nil && len(c.Exploit.NonLocusBasis) > 0 {
		var names []string
		for _, d := range c.Exploit.NonLocusBasis {
			names = append(names, d.Symbol.Package+"."+d.Symbol.Symbol)
		}
		nv.Limitations = append(nv.Limitations, fmt.Sprintf(
			"проверка уязвимости сужена экспертными решениями `non_locus` (ручное подтверждение, не автоматическое доказательство): %s",
			strings.Join(names, ", ")))
	}

	evID := c.EvidenceGraph.AddEvidence(domain.Evidence{
		Kind:    domain.EvidenceSourceSnippet,
		Quality: domain.QualityDeterministic,
		Source:  "go-analysis locus function unreachability check",
		Tool:    "goanalysis.Verifier",
		Content: fmt.Sprintf("%d locus function(s) verified unreached", len(subjects)),
	})
	nv.EvidenceIDs = append(nv.EvidenceIDs, evID)

	return setNeg(claim, nv)
}

func isInternalPkg(pkgPath string) bool {
	for _, seg := range strings.Split(pkgPath, "/") {
		if seg == "internal" {
			return true
		}
	}
	return false
}

func dirHasGoFiles(dir string) bool {
	if dir == "" {
		return false
	}
	has := false
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			base := d.Name()
			if p != dir && (base == ".git" || base == "vendor" || base == "testdata" || strings.HasPrefix(base, ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(d.Name(), ".go") && !strings.HasSuffix(d.Name(), "_test.go") {
			has = true
			return fs.SkipAll
		}
		return nil
	})
	return has
}

func scanProductSource(dir string) (map[string][]string, []string) {
	imports := map[string][]string{}
	var linknames []string
	fset := token.NewFileSet()
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			base := d.Name()
			if p != dir && (base == ".git" || base == "vendor" || base == "testdata" || strings.HasPrefix(base, ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") || strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, p, nil, parser.ImportsOnly|parser.ParseComments)
		if perr != nil {
			return nil
		}
		rel, rerr := filepath.Rel(dir, p)
		if rerr != nil {
			rel = p
		}
		for _, imp := range f.Imports {
			pkgPath, err := strconv.Unquote(imp.Path.Value)
			if err == nil {
				imports[pkgPath] = append(imports[pkgPath], rel)
			}
		}
		for _, cg := range f.Comments {
			for _, c := range cg.List {
				if strings.Contains(c.Text, "go:linkname") {
					linknames = append(linknames, c.Text)
				}
			}
		}
		return nil
	})
	return imports, linknames
}

func frameMatches(cs domain.CallSite, sym domain.SymbolRef) bool {
	if cs.Package != sym.Package {
		return false
	}
	if cs.Function == sym.Symbol {
		return true
	}
	if i := strings.LastIndexByte(sym.Symbol, '.'); i >= 0 {
		recv, fn := sym.Symbol[:i], sym.Symbol[i+1:]
		if cs.Function == fn && normalizeReceiver(cs.Receiver) == normalizeReceiver(recv) {
			return true
		}
	}
	return false
}

func normalizeReceiver(r string) string {
	r = strings.TrimPrefix(r, "(")
	r = strings.TrimSuffix(r, ")")
	return strings.TrimPrefix(r, "*")
}
