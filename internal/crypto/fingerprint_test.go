package crypto_test

import (
	"encoding/hex"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/crypto"
)

// TestFingerprint_IPv4_Mask24 verifies the /24 mask is applied to IPv4 addresses.
// GDPR: the individual IP must never appear in the output.
func TestFingerprint_IPv4_Mask24(t *testing.T) {
	ip := net.ParseIP("192.168.1.100")
	require.NotNil(t, ip)

	fp := crypto.Fingerprint(ip, 0)
	require.NotEmpty(t, fp)

	assert.NotContains(t, fp, "192.168.1.100",
		"fingerprint must not expose the individual IP (GDPR)")
}

// TestFingerprint_IPv4_SameSubnetSameFingerprint checks that two IPs in the same
// /24 produce the same fingerprint (the /24 mask collapses them to the same subnet).
func TestFingerprint_IPv4_SameSubnetSameFingerprint(t *testing.T) {
	ip1 := net.ParseIP("10.0.1.50")
	ip2 := net.ParseIP("10.0.1.200")
	require.NotNil(t, ip1)
	require.NotNil(t, ip2)

	fp1 := crypto.Fingerprint(ip1, 0)
	fp2 := crypto.Fingerprint(ip2, 0)

	assert.Equal(t, fp1, fp2,
		"two IPs in the same /24 must produce the same fingerprint")
}

// TestFingerprint_IPv4_DifferentSubnetDifferentFingerprint checks that IPs in
// different /24 subnets produce different fingerprints.
func TestFingerprint_IPv4_DifferentSubnetDifferentFingerprint(t *testing.T) {
	ip1 := net.ParseIP("10.0.1.1")
	ip2 := net.ParseIP("10.0.2.1")
	require.NotNil(t, ip1)
	require.NotNil(t, ip2)

	fp1 := crypto.Fingerprint(ip1, 0)
	fp2 := crypto.Fingerprint(ip2, 0)

	assert.NotEqual(t, fp1, fp2,
		"IPs in different /24 subnets must produce different fingerprints")
}

// TestFingerprint_IPv6_Mask48 verifies /48 masking: two addresses in the same /48
// but different /64 blocks must produce the same fingerprint.
func TestFingerprint_IPv6_Mask48(t *testing.T) {
	// 2001:db8:1:: and 2001:db8:1:cafe:: share the /48 prefix 2001:db8:1::/48.
	ip1 := net.ParseIP("2001:db8:1::1")
	ip2 := net.ParseIP("2001:db8:1:cafe::1")
	require.NotNil(t, ip1)
	require.NotNil(t, ip2)

	fp1 := crypto.Fingerprint(ip1, 0)
	fp2 := crypto.Fingerprint(ip2, 0)

	assert.Equal(t, fp1, fp2,
		"two IPv6 addresses in the same /48 must produce the same fingerprint (not /128 or /64)")
}

// TestFingerprint_IPv6_DifferentBlock48DifferentFingerprint checks that addresses
// in different /48 blocks produce different fingerprints.
func TestFingerprint_IPv6_DifferentBlock48DifferentFingerprint(t *testing.T) {
	ip1 := net.ParseIP("2001:db8:1::1")
	ip2 := net.ParseIP("2001:db8:2::1") // different /48
	require.NotNil(t, ip1)
	require.NotNil(t, ip2)

	fp1 := crypto.Fingerprint(ip1, 0)
	fp2 := crypto.Fingerprint(ip2, 0)

	assert.NotEqual(t, fp1, fp2,
		"IPv6 addresses in different /48 blocks must produce different fingerprints")
}

// TestFingerprint_IPv6_BypassPrevention verifies that an attacker cycling through
// many /128 addresses within the same /48 always gets the same fingerprint.
func TestFingerprint_IPv6_BypassPrevention(t *testing.T) {
	// Build 20 addresses all within 2600:1f14:dead::/48 but with different host parts.
	fingerprints := make([]string, 0, 20)
	for i := 0; i < 20; i++ {
		// Vary the last 80 bits (bits 48–128), keeping the /48 prefix fixed.
		addr := net.ParseIP("2600:1f14:dead::1")
		// Overwrite bytes 14 and 15 (the last 16 bits) to create distinct /128s.
		addr16 := addr.To16()
		require.NotNil(t, addr16)
		addr16[14] = byte(i >> 8)
		addr16[15] = byte(i)
		fp := crypto.Fingerprint(addr16, 0)
		fingerprints = append(fingerprints, fp)
	}
	require.NotEmpty(t, fingerprints)
	for i, fp := range fingerprints[1:] {
		assert.Equal(t, fingerprints[0], fp,
			"rotating /128 IPv6 addresses within the same /48 must all share one fingerprint (index %d)", i+1)
	}
}

// TestFingerprint_OutputIsHexString verifies the output is a valid lowercase hex string.
func TestFingerprint_OutputIsHexString(t *testing.T) {
	ip := net.ParseIP("203.0.113.5")
	require.NotNil(t, ip)

	fp := crypto.Fingerprint(ip, 0)
	require.NotEmpty(t, fp)

	decoded, err := hex.DecodeString(fp)
	assert.NoError(t, err,
		"fingerprint must be a valid hex string, not raw bytes or dotted-decimal IP")
	assert.NotEmpty(t, decoded)
}

// TestFingerprint_DifferentASNDifferentFingerprint verifies that the same subnet
// with different ASNs produces different fingerprints, separating CDN tenants.
func TestFingerprint_DifferentASNDifferentFingerprint(t *testing.T) {
	ip := net.ParseIP("198.51.100.42")
	require.NotNil(t, ip)

	fpASN1 := crypto.Fingerprint(ip, 7922)  // Comcast
	fpASN2 := crypto.Fingerprint(ip, 16509) // AWS

	assert.NotEqual(t, fpASN1, fpASN2,
		"same subnet with different ASNs must yield different fingerprints")
}

// TestFingerprint_SameASN_SameResult verifies ASN=0 produces stable output.
func TestFingerprint_SameASN_SameResult(t *testing.T) {
	ip := net.ParseIP("198.51.100.1")
	require.NotNil(t, ip)

	fp1 := crypto.Fingerprint(ip, 0)
	fp2 := crypto.Fingerprint(ip, 0)

	assert.Equal(t, fp1, fp2, "same IP + same ASN must always yield the same fingerprint")
}

// TestFingerprint_Loopback_NoPanic verifies 127.0.0.1 does not panic.
func TestFingerprint_Loopback_NoPanic(t *testing.T) {
	ip := net.ParseIP("127.0.0.1")
	require.NotNil(t, ip)

	// Must not panic — the function signature returns a plain string.
	fp := crypto.Fingerprint(ip, 0)
	assert.NotEmpty(t, fp, "loopback fingerprint must not be empty")
}

// TestFingerprint_TableDriven covers a matrix of same-vs-different subnet expectations.
func TestFingerprint_TableDriven(t *testing.T) {
	type tc struct {
		name      string
		ip1       string
		asn1      uint
		ip2       string
		asn2      uint
		wantEqual bool
	}
	cases := []tc{
		{"ipv4 same /24",             "172.16.5.10",      0, "172.16.5.250",     0,    true},
		{"ipv4 diff /24",             "172.16.5.1",       0, "172.16.6.1",       0,    false},
		{"ipv6 same /48",             "fd00:1:2::1",      0, "fd00:1:2:ff::1",   0,    true},
		{"ipv6 diff /48",             "fd00:1:2::1",      0, "fd00:1:3::1",      0,    false},
		{"same ip same asn",          "1.2.3.4",          42, "1.2.3.4",         42,   true},
		{"same subnet diff asn",      "1.2.3.4",          42, "1.2.3.100",       99,   false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ip1 := net.ParseIP(c.ip1)
			ip2 := net.ParseIP(c.ip2)
			require.NotNil(t, ip1, "failed to parse ip1: %s", c.ip1)
			require.NotNil(t, ip2, "failed to parse ip2: %s", c.ip2)

			fp1 := crypto.Fingerprint(ip1, c.asn1)
			fp2 := crypto.Fingerprint(ip2, c.asn2)

			if c.wantEqual {
				assert.Equal(t, fp1, fp2, "expected equal fingerprints")
			} else {
				assert.NotEqual(t, fp1, fp2, "expected different fingerprints")
			}
		})
	}
}
