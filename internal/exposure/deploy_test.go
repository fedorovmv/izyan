package exposure

import (
	"os"
	"path/filepath"
	"testing"

	"example.com/vuln-analyzer/internal/domain"
)

func TestScanDeploy(t *testing.T) {
	root := t.TempDir()
	mk := func(p, content string) {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mk("helm/app/templates/service.yaml", `apiVersion: v1
kind: Service
metadata:
  name: app
spec:
  type: LoadBalancer
  ports:
  - port: 443
`)
	mk("helm/app/templates/ingress.yaml", `apiVersion: networking.k8s.io/v1
kind: Ingress
spec:
  rules:
  - host: api.example.com
`)
	mk("k8s/pod.yaml", `kind: Deployment
spec:
  template:
    spec:
      hostNetwork: true
      containers:
      - ports:
        - hostPort: 9090
`)
	mk("docker-compose.yml", `services:
  app:
    ports:
      - "8080:8080"
`)
	// Outside deploy scope — must be ignored.
	mk("config/app.yaml", "kind: Service\nspec:\n  type: LoadBalancer\n")
	mk("tests/fixtures/svc.yaml", "kind: Ingress\nspec:\n  rules:\n  - host: x\n")

	facts, err := ScanDeploy(root)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, f := range facts {
		got[f.Target]++
		if f.Kind != "deployment" || f.Direction != "inbound" {
			t.Fatalf("bad fact: %+v", f)
		}
		if f.Scope != domain.ScopeAllInterfaces {
			t.Fatalf("deployment fact without public scope: %+v", f)
		}
	}
	want := map[string]int{
		"k8s:Service:LoadBalancer": 1,
		"k8s:Ingress":              1,
		"k8s:hostNetwork":          1,
		"k8s:hostPort":             1,
		"compose:published-port":   1,
	}
	for k, n := range want {
		if got[k] != n {
			t.Fatalf("target %s count=%d want %d (all: %v)", k, got[k], n, got)
		}
	}
	var ing *domain.ExposureFact
	for i, f := range facts {
		if f.Target == "k8s:Ingress" {
			ing = &facts[i]
		}
	}
	if ing == nil || ing.Address != "api.example.com" {
		t.Fatalf("ingress host not resolved: %+v", ing)
	}
}
