// The conformance suite is its own module so that the library's own build
// stays independent of it. `go build ./...` in the parent module skips a
// nested module, so the library compiles with no omni anywhere - and, more
// to the point, `go mod tidy` there cannot quietly add voxgig/omni to the
// published module's dependency graph. (The convention voxgig/struct#89
// set; omni register 4.13.)
//
// omni is REQUIRED BY ITS RELEASE TAG and resolved from the module proxy
// like any dependency (omni DOCS.md 8.3: `<port>/vX.Y.Z` is the tag shape
// Go mandates for a subdirectory module). The library under test is the
// parent module, replaced by a path RELATIVE TO THIS FILE - inside the
// repository, so it works on every machine and no go.work is needed.
module github.com/voxgig/sekreto/go/testutil

go 1.21

require (
	github.com/voxgig/omni/go v0.1.0
	github.com/voxgig/sekreto/go v0.0.0
)

require github.com/voxgig/plugin/go v0.0.0-20260901203214-91f294b7a228 // indirect

replace github.com/voxgig/sekreto/go => ../
