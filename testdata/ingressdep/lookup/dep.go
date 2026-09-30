package lookup

import "os"

func Sink(string) {}

func Entry() {
	value, _ := os.LookupEnv("PAYLOAD")
	Sink(value)
}
