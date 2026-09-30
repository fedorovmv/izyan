package funcvalue

import "os"

func Sink(string) {}
func Noop()       {}
func Read()       { Sink(os.Args[1]) }

var handler = Noop

func init() { handler = Read }

func Entry() { handler() }
