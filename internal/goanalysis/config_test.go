package goanalysis

import (
	"context"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
)

var tlsKnob = domain.SymbolRef{Package: "crypto/tls", Symbol: "Config.InsecureSkipVerify"}

func TestFieldAssignmentsFindsInsecure(t *testing.T) {
	ix := fixture(t, "tlsprod")
	got, err := ix.FieldAssignments(context.Background(), tlsKnob)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("assignments=%+v", got)
	}
	var lit, konst bool
	for _, a := range got {
		switch a.Source + ":" + a.Value {
		case "literal:true":
			lit = true
		case "const:true":
			konst = true
		}
	}
	if !lit || !konst {
		t.Fatalf("want literal:true and const:true assignments, got %+v", got)
	}
}

func TestFieldAssignmentsNone(t *testing.T) {
	ix := fixture(t, "tlssafe")
	got, err := ix.FieldAssignments(context.Background(), tlsKnob)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("unexpected assignments: %+v", got)
	}
}

func TestSymbolFieldType(t *testing.T) {
	ix := fixture(t, "tlssafe")
	kind, err := ix.SymbolFieldType(context.Background(), tlsKnob)
	if err != nil {
		t.Fatal(err)
	}
	if kind != "bool" {
		t.Fatalf("kind=%q want bool", kind)
	}
	// non-field symbol resolves to nothing
	kind, err = ix.SymbolFieldType(context.Background(), domain.SymbolRef{
		Package: "crypto/tls", Symbol: "Dial"})
	if err != nil || kind != "" {
		t.Fatalf("kind=%q err=%v", kind, err)
	}
}
