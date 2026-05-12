package handlers

// family_bindings_export_test.go — exports for the handlers_test package.
//
// Only compiled under `go test`, so the unexported resolver remains private
// in production builds. Used by deploy_family_bindings_test.go Test 7 to
// drive the resolver directly when verifying the FAMILY_BINDINGS_ENABLED
// flag, since the test app's config plumbing doesn't currently expose a
// knob for that flag mid-flight.

// HandlersTestResolveResourceBindings is the test-only export of
// resolveResourceBindings. Lives in a _test.go file so production builds
// never see it.
var HandlersTestResolveResourceBindings = resolveResourceBindings

// HandlersTestBindingError is the test-only export of the BindingError type.
type HandlersTestBindingError = BindingError
