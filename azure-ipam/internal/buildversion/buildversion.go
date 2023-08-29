package buildversion

// this will be populate by the Go compiler via
// the -ldflags, which insert dynamic information
// into the binary at build time
var BuildVersion string
