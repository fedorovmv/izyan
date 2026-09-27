package main

import (
	"fmt"
	"io"
	"net/http"

	"example.com/dep/vuln"
)

// The client authenticates every request, so the response body is
// EXTERNAL_AUTHENTICATED, not anonymous external input.
func main() {
	req, err := http.NewRequest("GET", "https://partner.example.com/feed", nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.SetBasicAuth("svc", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	fmt.Println(vuln.Parse(string(b)))
}

var token = "x"
