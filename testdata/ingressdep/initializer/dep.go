package initializer

import "os"

func Sink(string) {}

var _ = func() int {
	Sink(os.Args[1])
	return 1
}()

func Entry() {}
