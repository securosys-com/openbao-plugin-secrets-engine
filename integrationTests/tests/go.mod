module securosys.ch/integration/tests

replace securosys.ch/integration/client => ./../client
replace securosys.ch/test-helpers => ./../../testHelpers

go 1.19

require (
	securosys.ch/integration/client v0.0.0-00010101000000-000000000000
	securosys.ch/test-helpers v0.0.0-00010101000000-000000000000
)
