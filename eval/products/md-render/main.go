// md-render is a documentation preview service: clients POST a markdown
// document to /render and receive sanitized HTML back.
package main

import (
	"io"
	"log"
	"net/http"

	"github.com/gomarkdown/markdown"
	"github.com/gomarkdown/markdown/html"
	"github.com/gomarkdown/markdown/parser"
)

var extensions = parser.CommonExtensions | parser.AutoHeadingIDs
var htmlFlags = html.CommonFlags | html.HrefTargetBlank

func render(doc []byte) []byte {
	p := parser.NewWithExtensions(extensions)
	r := html.NewRenderer(html.RendererOptions{Flags: htmlFlags})
	return markdown.Render(p.Parse(doc), r)
}

func handleRender(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(render(body))
}

func main() {
	http.HandleFunc("/render", handleRender)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
