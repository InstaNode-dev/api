package minio

import (
	"testing"

	"github.com/stretchr/testify/assert"

	commonstorage "instant.dev/common/storageprovider"
)

// TestCustomerEndpointURL_EndpointWithScheme exercises the `://` short-circuit
// inside customerEndpointURL. madmin.New itself rejects an endpoint with a
// scheme, so this branch is unreachable through the public constructor — we
// build a Provider directly to cover it.
//
// The branch matters because a future operator-config migration that moves to
// publicURL=empty + endpoint=https://… would otherwise be silently broken;
// keeping this test in place defends against that.
func TestCustomerEndpointURL_EndpointWithScheme(t *testing.T) {
	p := &Provider{
		endpoint:  "https://endpoint.example.com:9000",
		publicURL: "",
		useTLS:    false,
	}
	got := p.customerEndpointURL()
	assert.Equal(t, "https://endpoint.example.com:9000", got,
		"endpoint already carrying a scheme must be returned as-is, no double-prefix")
}

// TestCustomerEndpointURL_PublicURLWinsOverEndpoint verifies the early-return
// when publicURL is non-empty — endpoint scheme/TLS flag are ignored. Already
// covered via the public PublicURL accessor but pinned here so the no-op
// path is explicit.
func TestCustomerEndpointURL_PublicURLWinsOverEndpoint(t *testing.T) {
	p := &Provider{
		endpoint:  "minio.example.com:9000",
		publicURL: "https://public.example.com",
		useTLS:    true,
	}
	assert.Equal(t, "https://public.example.com", p.customerEndpointURL())
}

// TestBuildPolicy_ContainsExpectedActions verifies the in-package buildPolicy
// helper emits the exact IAM action set + ARN pattern that the cross-tenant
// isolation contract requires. A regression here is a customer-visible
// permissions change.
func TestBuildPolicy_ContainsExpectedActions(t *testing.T) {
	pol := buildPolicy("instant-shared", "tok-abc")
	assert.Equal(t, "2012-10-17", pol.Version)
	require := assert.New(t)
	require.Len(pol.Statement, 2, "policy must have exactly two Allow statements (object ops + ListBucket)")

	// First statement: object ops scoped to the prefix.
	require.Equal("Allow", pol.Statement[0].Effect)
	require.Contains(pol.Statement[0].Action, "s3:GetObject")
	require.Contains(pol.Statement[0].Action, "s3:PutObject")
	require.Contains(pol.Statement[0].Action, "s3:DeleteObject")
	require.Equal([]string{"arn:aws:s3:::instant-shared/tok-abc/*"}, pol.Statement[0].Resource)

	// Second statement: ListBucket gated on s3:prefix.
	require.Equal("Allow", pol.Statement[1].Effect)
	require.Contains(pol.Statement[1].Action, "s3:ListBucket")
	require.Equal([]string{"arn:aws:s3:::instant-shared"}, pol.Statement[1].Resource)
	require.NotNil(pol.Statement[1].Condition)
	cond, ok := pol.Statement[1].Condition["StringLike"]
	require.True(ok)
	require.Equal([]string{"tok-abc/*"}, cond["s3:prefix"])
}

// TestNew_BuildAdminClientError exercises the madmin.New error path. madmin
// rejects an endpoint string that contains a scheme (sees "too many colons");
// the New helper must wrap that error with the call-site prefix so operators
// see "minio: build admin client".
func TestNew_BuildAdminClientError(t *testing.T) {
	_, err := New(commonstorage.Config{
		Endpoint:     "https://invalid-endpoint-with-scheme.example.com:9000",
		MasterKey:    "k",
		MasterSecret: "s",
	})
	if err == nil {
		t.Skip("madmin tolerated an endpoint with scheme — branch not exercised on this madmin version")
	}
	assert.Contains(t, err.Error(), "minio: build admin client",
		"madmin.New error must be wrapped with the call-site prefix")
}
