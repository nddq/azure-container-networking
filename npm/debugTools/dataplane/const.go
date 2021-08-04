package dataplane

import "errors"

const (
	// ANY string
	ANY string = "ANY"
	// MinOptionLength indicates the minimum length of an option
	MinOptionLength int = 2
	// MinUnsortedIPSetLength indicates the minimum length of an unsorted IP set's origin (i.e dst,dst)
	MinUnsortedIPSetLength int = 3
	// Base indicate the base for ParseInt
	Base int = 10
	// Bitsize indicate the bitsize for ParseInt
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

// error type
var (
	errSetNotExist      = errors.New("set does not exists")
	errInvalidIPAddress = errors.New("invalid ipaddress, no equivalent pod found")
	errInvalidInput     = errors.New("invalid input")
	errSetType          = errors.New("invalid set type")
)
