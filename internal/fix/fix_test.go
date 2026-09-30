package fix

import (
	"testing"

	"example.com/vuln-analyzer/internal/domain"
)

func TestPatchURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://github.com/golang/net/commit/abc123",
			"https://github.com/golang/net/commit/abc123.patch"},
		{"https://go.googlesource.com/net/+/abc123",
			"https://go.googlesource.com/net/+/abc123^!/?format=TEXT"},
		{"https://example.com/x/y.patch", "https://example.com/x/y.patch"},
		{"https://github.com/grpc/grpc-go/pull/9365",
			"https://github.com/grpc/grpc-go/pull/9365.diff"},
		{"https://github.com/grpc/grpc-go/pull/9365/",
			"https://github.com/grpc/grpc-go/pull/9365.diff"},
	}
	for _, c := range cases {
		got, err := patchURL(c.in)
		if err != nil {
			t.Fatalf("%s: %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("%s: got %s want %s", c.in, got, c.want)
		}
	}
	if _, err := patchURL("https://osv.dev/vulnerability/GO-1"); err == nil {
		t.Error("expected error for non-VCS url")
	}
}

func TestResolveFixRefs(t *testing.T) {
	v := domain.Vulnerability{
		FixedVersions: []string{"v0.33.0"},
		References: []domain.Reference{
			{Type: "ADVISORY", URL: "https://osv.dev/vulnerability/GO-1"},
			{Type: "FIX", URL: "https://github.com/golang/net/commit/deadbeef"},
			{Type: "WEB", URL: "https://example.com/blog"},
		},
	}
	refs := Resolver{}.Resolve(v)
	if len(refs) != 1 || refs[0].Kind != "commit" {
		t.Fatalf("refs=%+v", refs)
	}
	if refs[0].Versions[0] != "v0.33.0" {
		t.Fatalf("versions=%v", refs[0].Versions)
	}
}

// GO-2026-6443-style FIX references point at a pull request, not a commit —
// the resolver must recognize them so the fix diff can narrow root causes.
func TestResolveFixRefsPullRequest(t *testing.T) {
	v := domain.Vulnerability{
		References: []domain.Reference{
			{Type: "FIX", URL: "https://github.com/grpc/grpc-go/pull/9365"},
			{Type: "WEB", URL: "https://gitlab.com/o/r/-/merge_requests/1"},
		},
	}
	refs := Resolver{}.Resolve(v)
	if len(refs) != 1 || refs[0].URL != "https://github.com/grpc/grpc-go/pull/9365" {
		t.Fatalf("refs=%+v", refs)
	}
}

func TestParseDiff(t *testing.T) {
	patch := `diff --git a/html/parse.go b/html/parse.go
index 111..222 100644
--- a/html/parse.go
+++ b/html/parse.go
@@ -100,7 +100,8 @@ func (p *parser) readUntilCloseTag() error {
-	old()
+	newCall()
@@ -200,3 +200,4 @@ func Parse(r io.Reader) (*Node, error) {
-	x()
+	y()
+	z()
`
	files := Parse(patch)
	if len(files) != 1 || files[0].Path != "html/parse.go" {
		t.Fatalf("files=%+v", files)
	}
	want := map[string]bool{"parser.readUntilCloseTag": true, "Parse": true}
	for _, s := range files[0].Symbols {
		delete(want, s)
	}
	if len(want) != 0 {
		t.Fatalf("missing symbols %v in %+v", want, files[0].Symbols)
	}
}
