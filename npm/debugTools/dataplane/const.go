package dataplane

const (
	// ANY string
	ANY string = "ANY"
	// Minimum length of an option
	MinOptionLength int = 2
	// Minimum length of an unsorted IP set's origin (i.e dst,dst)
	MinUnsortedIPSetLength int = 3
	// Base
	Base int = 10
	// Bitsize
	Bitsize int = 32
)

// RequiredChains contains names of chain that will be include in the result of the converter
var RequiredChains = []string{
	"AZURE-NPM-INGRESS-DROPS",
	"AZURE-NPM-INGRESS-FROM",
	"AZURE-NPM-INGRESS-PORT",
	"AZURE-NPM-EGRESS-DROPS",
	"AZURE-NPM-EGRESS-PORT",
	"AZURE-NPM-EGRESS-TO",
}
