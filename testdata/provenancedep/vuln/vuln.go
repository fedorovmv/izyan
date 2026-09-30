package vuln

import "os"

func Parse(string) {}

func Value(any) {}

func Load(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

func Identity(s string) string { return s }
