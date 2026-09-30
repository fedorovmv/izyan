package fix

import "testing"

// defectSiteDiff mirrors the GO-2026-6443 fix shape: one hunk guards the
// faulting index at the defect site, another adds an upstream rejection in
// a function that never performs the faulting operation.
const defectSiteDiff = `diff --git a/internal/transport/http2_server.go b/internal/transport/http2_server.go
index 111..222 100644
--- a/internal/transport/http2_server.go
+++ b/internal/transport/http2_server.go
@@ -522,6 +522,12 @@ func (t *http2Server) operateHeaders(ctx context.Context, frame *http2.MetaHeade
 		delete(mdata, "host")
 	}
 
+	// If :authority is still missing, reject the request as invalid.
+	if len(mdata[":authority"]) == 0 {
+		t.writeEarlyAbort(streamID, s.contentSubtype)
+		return nil
+	}
 	if frame.StreamEnded() {
 		s.state = streamReadDone
 	}
diff --git a/internal/xds/server/routing.go b/internal/xds/server/routing.go
index 333..444 100644
--- a/internal/xds/server/routing.go
+++ b/internal/xds/server/routing.go
@@ -61,11 +61,14 @@ func RouteAndProcess(ctx context.Context) error {
 	if !ok {
 		return errors.New("missing metadata")
 	}
 	authority := md.Get(":authority")
-	// authority[0] is safe because of the guarantee mentioned above.
+	if len(authority) == 0 {
+		return rc.statusErrWithNodeID(codes.Internal, "no :authority header")
+	}
 	vh := findBestMatchingVirtualHostServer(authority[0], rc.vhs)
 	if vh == nil {
 		return rc.statusErrWithNodeID(codes.Unavailable, "no Virtual Host")
 	}
diff --git a/internal/xds/server/routing_test.go b/internal/xds/server/routing_test.go
index 555..666 100644
--- a/internal/xds/server/routing_test.go
+++ b/internal/xds/server/routing_test.go
@@ -104,3 +104,9 @@
+func (s) TestRouteAndProcess_MissingAuthority(t *testing.T) {
+	x := []string{}
+	_ = x[0]
+}
`

func fileByPath(p Patch, path string) *File {
	for i := range p {
		if p[i].Path == path {
			return &p[i]
		}
	}
	return nil
}

// The hunk that adds a guard directly over a surviving faulting use marks
// the enclosing function as the defect site.
func TestParseGuardedDefectSite(t *testing.T) {
	p := Parse(defectSiteDiff)
	f := fileByPath(p, "internal/xds/server/routing.go")
	if f == nil {
		t.Fatalf("routing.go not parsed: %+v", p)
	}
	found := false
	for _, s := range f.GuardedSymbols {
		if s == "RouteAndProcess" {
			found = true
		}
	}
	if !found {
		t.Fatalf("RouteAndProcess not flagged as guarded defect site: %+v", f.GuardedSymbols)
	}
	if ops := f.GuardOperands["RouteAndProcess"]; len(ops) != 1 || ops[0] != "authority" {
		t.Fatalf("guard operands=%v", f.GuardOperands)
	}
}

// An upstream validation hunk guards a value the function never uses
// faultingly — the guard alone must not mark it a defect site, and the
// operand must still be recorded for body-level verification.
func TestParseEnablerNotDefectSite(t *testing.T) {
	p := Parse(defectSiteDiff)
	f := fileByPath(p, "internal/transport/http2_server.go")
	if f == nil {
		t.Fatal("http2_server.go not parsed")
	}
	for _, s := range f.GuardedSymbols {
		if s == "http2Server.operateHeaders" {
			t.Fatalf("enabler flagged as defect site: %+v", f.GuardedSymbols)
		}
	}
	if ops := f.GuardOperands["http2Server.operateHeaders"]; len(ops) != 1 || ops[0] != `mdata[":authority"]` {
		t.Fatalf("guard operands=%v", f.GuardOperands)
	}
}

// A guard with no faulting use anywhere in the hunk is still recorded with
// its operand — only the GuardedSymbols flag stays unset.
func TestParseGuardWithoutFaultingUse(t *testing.T) {
	patch := `diff --git a/srv/handler.go b/srv/handler.go
index 1..2 100644
--- a/srv/handler.go
+++ b/srv/handler.go
@@ -10,3 +10,7 @@ func Handle(req *Request) error {
+	if len(items) == 0 {
+		return errEmpty
+	}
 	return process(req)
 }
`
	f := Parse(patch)[0]
	if len(f.GuardedSymbols) != 0 {
		t.Fatalf("unexpected guarded symbols: %v", f.GuardedSymbols)
	}
	if ops := f.GuardOperands["Handle"]; len(ops) != 1 || ops[0] != "items" {
		t.Fatalf("guard operands=%v", f.GuardOperands)
	}
}

// A nil guard over a pointer dereferenced in the same hunk is a defect-site
// signature too.
func TestParseNilGuardedDefectSite(t *testing.T) {
	patch := `diff --git a/net/dial.go b/net/dial.go
index 1..2 100644
--- a/net/dial.go
+++ b/net/dial.go
@@ -30,4 +30,8 @@ func Dial(addr string) (*Conn, error) {
 	conn := lookup(addr)
+	if conn == nil {
+		return nil, errNoConn
+	}
 	return conn.RemoteAddr(), nil
 }
`
	f := Parse(patch)[0]
	found := false
	for _, s := range f.GuardedSymbols {
		if s == "Dial" {
			found = true
		}
	}
	if !found {
		t.Fatalf("Dial not flagged: %v", f.GuardedSymbols)
	}
}

// Method hunks record receiver-qualified symbols; guards inside a method
// hunk flag "Type.Method".
func TestParseMethodGuardedSite(t *testing.T) {
	patch := `diff --git a/srv/srv.go b/srv/srv.go
index 1..2 100644
--- a/srv/srv.go
+++ b/srv/srv.go
@@ -9,4 +9,7 @@ func (s *server) Serve() error {
+	if len(s.conns) == 0 {
+		return errNone
+	}
 	return s.conns[0].Close()
 }
`
	f := Parse(patch)[0]
	found := false
	for _, s := range f.GuardedSymbols {
		if s == "server.Serve" {
			found = true
		}
	}
	if !found {
		t.Fatalf("server.Serve not flagged: %+v", f)
	}
}
