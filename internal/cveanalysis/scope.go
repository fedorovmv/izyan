package cveanalysis

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"example.com/vuln-analyzer/internal/domain"
)

type TargetCall struct {
	Package  string
	Function string
}

func (t TargetCall) Canonical() string {
	return t.Package + "." + t.Function
}

type ScopeAnalyzer struct{}

func NewScopeAnalyzer() *ScopeAnalyzer {
	return &ScopeAnalyzer{}
}

func (s *ScopeAnalyzer) InspectCalls(ctx context.Context, repoPath string, targets []TargetCall) (domain.ProductExposureFacts, error) {
	facts := domain.ProductExposureFacts{}
	if err := ctx.Err(); err != nil {
		return facts, err
	}

	foundMap := make(map[string]bool)

	fset := token.NewFileSet()
	err := filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if path == repoPath {
				return err
			}
			return nil
		}
		if info == nil {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if info.IsDir() {
			if path != repoPath && (strings.HasPrefix(info.Name(), ".") || info.Name() == "vendor" || info.Name() == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		node, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return nil
		}

		// Map local import names -> canonical package path
		importMap := make(map[string]string)
		for _, imp := range node.Imports {
			pkgPath, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				continue
			}
			localName := ""
			if imp.Name != nil {
				localName = imp.Name.Name
			} else {
				// default local name is last element of path
				parts := strings.Split(pkgPath, "/")
				localName = parts[len(parts)-1]
			}
			if localName != "" && localName != "_" {
				importMap[localName] = pkgPath
			}
		}

		ast.Inspect(node, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			ident, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}

			canonicalPkg, hasPkg := importMap[ident.Name]
			if !hasPkg {
				return true
			}

			funcName := sel.Sel.Name
			for _, target := range targets {
				if target.Package == canonicalPkg && target.Function == funcName {
					foundMap[target.Canonical()] = true
				}
			}
			return true
		})

		return nil
	})

	if err != nil {
		return facts, err
	}

	seen := make(map[string]bool)
	for _, target := range targets {
		cName := target.Canonical()
		if seen[cName] {
			continue
		}
		seen[cName] = true
		if foundMap[cName] {
			facts.EntrypointConstructors = append(facts.EntrypointConstructors, cName)
		} else {
			facts.AbsentConstructors = append(facts.AbsentConstructors, cName)
		}
	}

	return facts, nil
}
