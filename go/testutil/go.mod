// The conformance suite is its own module so that the library's own build
// stays independent of it. `go build ./...` in the parent module skips a
// nested module, so the library compiles with no sibling omni checkout and
// no workspace - and, more to the point, `go mod tidy` there cannot quietly
// add voxgig/omni to the published module's dependency graph. (The
// convention voxgig/struct#89 set; omni register 4.13.)
//
// Neither require below is ever resolved from a proxy: the go.work written
// by the parent Makefile supplies both from local checkouts.
module github.com/voxgig/sekreto/go/testutil

go 1.21

require (
	github.com/voxgig/omni/go v0.0.0
	github.com/voxgig/sekreto/go v0.0.0
)
