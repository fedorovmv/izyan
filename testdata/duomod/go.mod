module example.com/duomod

go 1.23

require (
	example.com/dep v0.0.0
	example.com/dep5 v0.0.0
)

replace (
	example.com/dep => ../dep
	example.com/dep5 => ../dep5
)
