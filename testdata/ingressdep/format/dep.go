package format

import (
	"fmt"
	"os"
)

func Sink(string) {}

type formatter struct{}

func (formatter) String() string { return os.Args[1] }

func Entry() { _ = fmt.Sprint(formatter{}) }
