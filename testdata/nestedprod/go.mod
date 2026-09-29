module example.com/nestedprod

go 1.23

require (
	example.com/nesteddep v0.0.0
	example.com/nesteddep/v2 v2.0.0
)

replace example.com/nesteddep => ../nesteddep
replace example.com/nesteddep/v2 => ../nesteddep/v2
