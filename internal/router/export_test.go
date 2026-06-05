package router

// export_test.go — re-export package-private symbols for the
// _test.go siblings that live in `router_test` (external test
// package). Keeping these in a `_test.go` file means they're
// compiled only during `go test` and never leak into the
// distributed binary.

// ExportedMakeSecurityTxtHandler is the unit-test-facing alias for
// makeSecurityTxtHandler. The handler builder is package-private in
// production because the only legitimate consumer is router.New; the
// alias exists so the patch-coverage gate (100% of changed lines)
// can directly cover the closure body without standing up the full
// router New(...) wiring (which needs Postgres + Redis + gRPC).
var ExportedMakeSecurityTxtHandler = makeSecurityTxtHandler

// ExportedWireAnalyticsEmitter is the unit-test-facing alias for
// wireAnalyticsEmitter, so the WS4 emitter-construction logic (backend
// selection + NR failure-hook wiring) can be covered without standing up the
// full router New(...) (which needs Postgres + Redis + gRPC).
var ExportedWireAnalyticsEmitter = wireAnalyticsEmitter
