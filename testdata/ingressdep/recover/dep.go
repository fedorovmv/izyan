package recover

func Sink(string) {}

func Entry() {
	defer func() { Sink(recover().(string)) }()
	panic("literal")
}
