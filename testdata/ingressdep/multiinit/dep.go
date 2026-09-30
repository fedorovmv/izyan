package multiinit

import "os"

func Sink(string) {}

func init() {}

func init() { Sink(os.Args[1]) }

func Entry() {}
