package goanalysis

import (
	"context"
	"encoding/json"
	"go/token"
	"go/types"
	"testing"

	"example.com/vuln-analyzer/internal/domain"
)

func TestCanonicalByteIORequiresExactNonvariadicSignature(t *testing.T) {
	byteSlice := types.NewSlice(types.Typ[types.Byte])
	errorType := types.Universe.Lookup("error").Type()
	newTuple := func(ts ...types.Type) *types.Tuple {
		vars := make([]*types.Var, len(ts))
		for i, typ := range ts {
			vars[i] = types.NewVar(token.NoPos, nil, "", typ)
		}
		return types.NewTuple(vars...)
	}
	newSignature := func(param types.Type, result types.Type, variadic bool) *types.Signature {
		return types.NewSignatureType(nil, nil, nil,
			newTuple(param), newTuple(types.Typ[types.Int], result), variadic)
	}
	newNamed := func(name string, underlying types.Type) types.Type {
		obj := types.NewTypeName(token.NoPos, nil, name, nil)
		return types.NewNamed(obj, underlying, nil)
	}
	for _, tc := range []struct {
		name string
		sig  *types.Signature
		want bool
	}{
		{name: "canonical", sig: newSignature(byteSlice, errorType, false), want: true},
		{name: "named byte slice", sig: newSignature(newNamed("Bytes", byteSlice), errorType, false)},
		{name: "named int result", sig: newSignature(byteSlice, errorType, false)},
		{name: "variadic byte parameter", sig: newSignature(byteSlice, errorType, true)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "named int result" {
				tc.sig = types.NewSignatureType(nil, nil, nil,
					newTuple(byteSlice),
					newTuple(newNamed("Count", types.Typ[types.Int]), errorType), false)
			}
			if got := canonicalByteIO(tc.sig); got != tc.want {
				t.Fatalf("canonicalByteIO(%s)=%t want %t", tc.name, got, tc.want)
			}
		})
	}
}

func TestWriterOnlyTypeWithNoncanonicalReadRemainsWriterOnly(t *testing.T) {
	byteSlice := types.NewSlice(types.Typ[types.Byte])
	errorType := types.Universe.Lookup("error").Type()
	newTuple := func(ts ...types.Type) *types.Tuple {
		vars := make([]*types.Var, len(ts))
		for i, typ := range ts {
			vars[i] = types.NewVar(token.NoPos, nil, "", typ)
		}
		return types.NewTuple(vars...)
	}
	newNamed := func(name string, underlying types.Type) types.Type {
		obj := types.NewTypeName(token.NoPos, nil, name, nil)
		return types.NewNamed(obj, underlying, nil)
	}
	method := func(named *types.Named, name string, param, count types.Type, variadic bool) {
		recv := types.NewVar(token.NoPos, nil, "", named)
		sig := types.NewSignatureType(recv, nil, nil,
			newTuple(param), newTuple(count, errorType), variadic)
		named.AddMethod(types.NewFunc(token.NoPos, nil, name, sig))
	}
	for _, tc := range []struct {
		name         string
		readParam    types.Type
		readCount    types.Type
		readVariadic bool
		want         bool
	}{
		{name: "no reader", want: true},
		{name: "canonical reader", readParam: byteSlice, readCount: types.Typ[types.Int]},
		{name: "named result reader", readParam: byteSlice, readCount: newNamed("Count", types.Typ[types.Int]), want: true},
		{name: "variadic reader", readParam: byteSlice, readCount: types.Typ[types.Int], readVariadic: true, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			named := types.NewNamed(types.NewTypeName(token.NoPos, nil, "Conn", nil),
				types.NewStruct(nil, nil), nil)
			method(named, "Write", byteSlice, types.Typ[types.Int], false)
			if tc.readParam != nil {
				method(named, "Read", tc.readParam, tc.readCount, tc.readVariadic)
			}
			if got := writerOnlyType(named); got != tc.want {
				t.Fatalf("writerOnlyType(%s)=%t want %t", tc.name, got, tc.want)
			}
		})
	}
}

func TestTraceMarksOnlyWriterParametersAsPayloadUnproven(t *testing.T) {
	ix := fixture(t, "writerpayloadprod")
	ctx := context.Background()
	trace := func(symbol string, arg int) domain.DataFlow {
		t.Helper()
		sites, err := ix.FindCallers(ctx, domain.SymbolRef{
			Package: "example.com/writerpayloadprod",
			Symbol:  symbol,
		})
		if err != nil || len(sites) != 1 {
			t.Fatalf("%s callers=%+v err=%v", symbol, sites, err)
		}
		flow, _, err := ix.TraceArgument(ctx, sites[0], arg)
		if err != nil {
			t.Fatal(err)
		}
		return flow
	}
	assertMarked := func(name string, flow domain.DataFlow, want bool) {
		t.Helper()
		if flow.PayloadUnproven != want {
			t.Fatalf("%s PayloadUnproven=%t want %t (%s)", name, flow.PayloadUnproven, want, flow.Summary)
		}
	}

	writer := trace("record", 0)
	if writer.Origin != domain.OriginExternalUntrusted {
		t.Fatalf("writer origin=%s want EXTERNAL_UNTRUSTED (%s)", writer.Origin, writer.Summary)
	}
	assertMarked("writer parameter", writer, true)
	payloadArg := trace("record", 1)
	assertMarked("byte payload parameter", payloadArg, false)
	assertMarked("reader-writer parameter", trace("recordBoth", 0), false)
	assertMarked("reader parameter", trace("recordReader", 0), false)
	assertMarked("net.Conn parameter", trace("recordConn", 0), false)
	assertMarked("noncanonical Read method", trace("recordFakeRead", 0), true)
	assertMarked("variadic writer parameter 0", trace("recordMany", 0), true)
	assertMarked("variadic writer parameter 1", trace("recordMany", 1), true)

	methodSites, err := ix.FindCallers(ctx, domain.SymbolRef{
		Package: "example.com/writerpayloadprod",
		Symbol:  "writerConn.Emit",
	})
	if err != nil || len(methodSites) != 1 {
		t.Fatalf("writerConn.Emit callers=%+v err=%v", methodSites, err)
	}
	methodReceiver, _, err := ix.TraceArgument(ctx, methodSites[0], 0)
	if err != nil {
		t.Fatal(err)
	}
	assertMarked("method-expression receiver", methodReceiver, true)
	if methodReceiver.Origin != domain.OriginExternalUntrusted {
		t.Fatalf("method-expression receiver origin=%s want EXTERNAL_UNTRUSTED (%s)",
			methodReceiver.Origin, methodReceiver.Summary)
	}

	payload := trace("recordPayload", 0)
	if payload.Origin != domain.OriginExternalUntrusted {
		t.Fatalf("payload origin=%s want EXTERNAL_UNTRUSTED (%s)", payload.Origin, payload.Summary)
	}
	assertMarked("payload parameter", payload, false)

	recordSites, err := ix.FindCallers(ctx, domain.SymbolRef{
		Package: "example.com/writerpayloadprod",
		Symbol:  "record",
	})
	if err != nil || len(recordSites) != 1 {
		t.Fatalf("record callers=%+v err=%v", recordSites, err)
	}
	allFlows, _, err := ix.TraceAllArguments(ctx, recordSites[0])
	if err != nil || len(allFlows) != 2 {
		t.Fatalf("record flows=%+v err=%v", allFlows, err)
	}
	assertMarked("TraceAllArguments writer slot", allFlows[0], true)
	assertMarked("TraceAllArguments payload slot", allFlows[1], false)

	encoded, err := json.Marshal(writer)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatal(err)
	}
	if wire["payload_unproven"] != true {
		t.Fatalf("serialized writer flow=%s, payload_unproven should be true", encoded)
	}
}

func TestVerifyFalseStillContradictsOnExternalWriterOrigin(t *testing.T) {
	ix := fixture(t, "writerpayloadprod")
	subject := domain.SymbolRef{Package: "example.com/writerpayloadprod", Symbol: "record"}
	cond := domain.Condition{
		ID: "C-INPUT", Kind: domain.ConditionAttackerControl,
		Subject: &subject, ArgIndex: -1,
	}
	c := &domain.AnalysisCase{}
	claim := Verifier{Source: ix}.VerifyFalse(context.Background(), c,
		domain.Claim{ConditionID: cond.ID, Result: domain.ClaimFalse}, cond)
	if claim.NegativeVerification == nil || claim.NegativeVerification.Status != domain.NegativeContradicted {
		t.Fatalf("external writer origin did not contradict FALSE: %+v", claim.NegativeVerification)
	}
}
