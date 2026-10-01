package cveanalysis_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"example.com/vuln-analyzer/internal/cveanalysis"
)

func TestScopeAnalyzer_ResolvesImportAliases(t *testing.T) {
	tmpDir := t.TempDir()
	code := `package main

import mygrpc "google.golang.org/grpc"

func run() {
	_ = mygrpc.NewServer()
}
`
	if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte(code), 0644); err != nil {
		t.Fatal(err)
	}

	analyzer := cveanalysis.NewScopeAnalyzer()
	targets := []cveanalysis.TargetCall{
		{Package: "google.golang.org/grpc", Function: "NewServer"},
		{Package: "google.golang.org/grpc/xds", Function: "NewGRPCServer"},
	}

	facts, err := analyzer.InspectCalls(context.Background(), tmpDir, targets)
	if err != nil {
		t.Fatalf("InspectCalls failed: %v", err)
	}

	if len(facts.EntrypointConstructors) != 1 || facts.EntrypointConstructors[0] != "google.golang.org/grpc.NewServer" {
		t.Errorf("got %v, want ['google.golang.org/grpc.NewServer']", facts.EntrypointConstructors)
	}
	if len(facts.AbsentConstructors) != 1 || facts.AbsentConstructors[0] != "google.golang.org/grpc/xds.NewGRPCServer" {
		t.Errorf("got %v, want ['google.golang.org/grpc/xds.NewGRPCServer']", facts.AbsentConstructors)
	}
}

func TestScopeAnalyzer_IgnoresTestsAndSpecialDirs(t *testing.T) {
	tmpDir := t.TempDir()

	// Subdirs
	vendorDir := filepath.Join(tmpDir, "vendor", "somepkg")
	testdataDir := filepath.Join(tmpDir, "testdata")
	dotDir := filepath.Join(tmpDir, ".hidden")
	subDir := filepath.Join(tmpDir, "pkg", "sub")

	for _, d := range []string{vendorDir, testdataDir, dotDir, subDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}

	// 1. _test.go file in root (should be ignored)
	testFile := `package main
import "google.golang.org/grpc/xds"
func TestSomething() { _ = xds.NewGRPCServer() }
`
	if err := os.WriteFile(filepath.Join(tmpDir, "main_test.go"), []byte(testFile), 0644); err != nil {
		t.Fatal(err)
	}

	// 2. file in vendor (should be ignored)
	vendorFile := `package somepkg
import "google.golang.org/grpc/xds"
func VendorCall() { _ = xds.NewGRPCServer() }
`
	if err := os.WriteFile(filepath.Join(vendorDir, "vendor.go"), []byte(vendorFile), 0644); err != nil {
		t.Fatal(err)
	}

	// 3. file in testdata (should be ignored)
	testdataFile := `package testdata
import "google.golang.org/grpc/xds"
func TestdataCall() { _ = xds.NewGRPCServer() }
`
	if err := os.WriteFile(filepath.Join(testdataDir, "data.go"), []byte(testdataFile), 0644); err != nil {
		t.Fatal(err)
	}

	// 4. file in dot directory (should be ignored)
	dotFile := `package hidden
import "google.golang.org/grpc/xds"
func HiddenCall() { _ = xds.NewGRPCServer() }
`
	if err := os.WriteFile(filepath.Join(dotDir, "hidden.go"), []byte(dotFile), 0644); err != nil {
		t.Fatal(err)
	}

	// 5. valid file in sub directory (should be detected)
	validFile := `package sub
import "google.golang.org/grpc"
func ValidCall() { _ = grpc.NewServer() }
`
	if err := os.WriteFile(filepath.Join(subDir, "sub.go"), []byte(validFile), 0644); err != nil {
		t.Fatal(err)
	}

	analyzer := cveanalysis.NewScopeAnalyzer()
	targets := []cveanalysis.TargetCall{
		{Package: "google.golang.org/grpc", Function: "NewServer"},
		{Package: "google.golang.org/grpc/xds", Function: "NewGRPCServer"},
	}

	facts, err := analyzer.InspectCalls(context.Background(), tmpDir, targets)
	if err != nil {
		t.Fatalf("InspectCalls failed: %v", err)
	}

	if len(facts.EntrypointConstructors) != 1 || facts.EntrypointConstructors[0] != "google.golang.org/grpc.NewServer" {
		t.Errorf("got entrypoints %v, want ['google.golang.org/grpc.NewServer']", facts.EntrypointConstructors)
	}
	if len(facts.AbsentConstructors) != 1 || facts.AbsentConstructors[0] != "google.golang.org/grpc/xds.NewGRPCServer" {
		t.Errorf("got absent %v, want ['google.golang.org/grpc/xds.NewGRPCServer']", facts.AbsentConstructors)
	}
}

func TestScopeAnalyzer_DefaultImport(t *testing.T) {
	tmpDir := t.TempDir()
	code := `package main

import "google.golang.org/grpc"

func run() {
	_ = grpc.NewServer()
}
`
	if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte(code), 0644); err != nil {
		t.Fatal(err)
	}

	analyzer := cveanalysis.NewScopeAnalyzer()
	targets := []cveanalysis.TargetCall{
		{Package: "google.golang.org/grpc", Function: "NewServer"},
	}

	facts, err := analyzer.InspectCalls(context.Background(), tmpDir, targets)
	if err != nil {
		t.Fatalf("InspectCalls failed: %v", err)
	}

	if len(facts.EntrypointConstructors) != 1 || facts.EntrypointConstructors[0] != "google.golang.org/grpc.NewServer" {
		t.Errorf("got %v, want ['google.golang.org/grpc.NewServer']", facts.EntrypointConstructors)
	}
	if len(facts.AbsentConstructors) != 0 {
		t.Errorf("got %v, want empty", facts.AbsentConstructors)
	}
}

func TestScopeAnalyzer_ContextCancelled(t *testing.T) {
	tmpDir := t.TempDir()
	code := `package main
func run() {}
`
	if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte(code), 0644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	analyzer := cveanalysis.NewScopeAnalyzer()
	targets := []cveanalysis.TargetCall{
		{Package: "google.golang.org/grpc", Function: "NewServer"},
	}

	_, err := analyzer.InspectCalls(ctx, tmpDir, targets)
	if err == nil {
		t.Fatal("expected error on cancelled context, got nil")
	}
}
