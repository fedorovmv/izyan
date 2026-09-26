package main

import (
	"fmt"
	"io"
	"net/http"
	"os"

	"example.com/dep/vuln"
)

// The endpoint is operator-configured, so the response body is internal
// service data — trust boundary is a deployment property, attacker
// control must resolve to INTERNAL_SERVICE, not external-untrusted.
func main() {
	resp, err := http.Get(os.Getenv("SVC_URL"))
	if err != nil {
		return
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	fmt.Println(vuln.Parse(string(b)))
}
