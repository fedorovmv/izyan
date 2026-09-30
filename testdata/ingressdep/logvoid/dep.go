package logvoid

import (
	"log"
	"os"
)

func Sink(string) {}

type formatter struct{}

func (formatter) String() string {
	Sink(os.Args[1])
	return "safe"
}

func Entry() {
	log.Print(formatter{})
	log.Println("constant")
}
