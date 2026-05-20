package middleware

import (
	"log/slog"
	"net"
	"sync"

	"github.com/gofiber/fiber/v2"
	"github.com/oschwald/maxminddb-golang"
	"instant.dev/internal/metrics"
)

// cloudASNs maps well-known ASNs to their cloud vendor slug.
var cloudASNs = map[uint]string{
	16509:  "aws",
	14618:  "aws",
	15169:  "gcp",
	396982: "gcp",
	8075:   "azure",
	8070:   "azure",
	36459:  "github-actions",
	13335:  "cloudflare",
	54113:  "fastly",
}

// geoRecord is the subset of MaxMind fields we care about.
type geoRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

// asnRecord is the MaxMind ASN database record.
type asnRecord struct {
	AutonomousSystemNumber       uint   `maxminddb:"autonomous_system_number"`
	AutonomousSystemOrganization string `maxminddb:"autonomous_system_organization"`
}

// GeoDBs holds open MaxMind database readers.
type GeoDBs struct {
	City *maxminddb.Reader
	ASN  *maxminddb.Reader
}

// GeoEnrichResult holds all geo fields derived from the client IP.
type GeoEnrichResult struct {
	CountryCode string
	ASN         uint
	OrgName     string
	CloudVendor string
}

var warnOnce sync.Once

// GeoEnrich returns a middleware that performs MaxMind lookups and stores results in Fiber locals.
// If dbs is nil (MaxMind files not present), defaults are used and a warning is logged once.
//
// P2 (CIRCUIT-RETRY-AUDIT-2026-05-20): the silent-fail-open path
// (country=XX, vendor=unknown when MMDB missing) now also bumps the
// `instant_fail_open_events_total{subsystem="geoip"}` counter so the
// "MMDB pod is missing its DB" condition becomes observable. The
// behaviour is unchanged — every request still gets safe defaults — but
// operators no longer learn about the failure mode only when a customer
// reports wrong-currency pricing.
func GeoEnrich(dbs *GeoDBs) fiber.Handler {
	if dbs == nil {
		warnOnce.Do(func() {
			slog.Warn("geo.middleware: MaxMind GeoLite2 database not loaded — using defaults (country=XX, vendor=unknown)")
		})
	}

	return func(c *fiber.Ctx) error {
		result := &GeoEnrichResult{
			CountryCode: "XX",
			ASN:         0,
			OrgName:     "unknown",
			CloudVendor: "unknown",
		}

		if dbs != nil {
			ipStr := c.IP()
			ip := net.ParseIP(ipStr)
			if ip != nil {
				enrichFromIP(ip, dbs, result)
			}
		} else {
			// P2: emit a fail-open metric so the "missing MMDB" condition
			// is alertable instead of silent. Bounded label cardinality:
			// the counter is incremented per-request when the DB is
			// absent, which is exactly the signal we want.
			metrics.FailOpenEvents.WithLabelValues("geoip", "mmdb_missing").Inc()
		}

		c.Locals("country", result.CountryCode)
		c.Locals("asn", result.ASN)
		c.Locals("org_name", result.OrgName)
		c.Locals("cloud_vendor", result.CloudVendor)

		return c.Next()
	}
}

func enrichFromIP(ip net.IP, dbs *GeoDBs, result *GeoEnrichResult) {
	if dbs.City != nil {
		var rec geoRecord
		if err := dbs.City.Lookup(ip, &rec); err == nil {
			if rec.Country.ISOCode != "" {
				result.CountryCode = rec.Country.ISOCode
			}
		}
	}

	if dbs.ASN != nil {
		var rec asnRecord
		if err := dbs.ASN.Lookup(ip, &rec); err == nil {
			result.ASN = rec.AutonomousSystemNumber
			result.OrgName = rec.AutonomousSystemOrganization
			if vendor, ok := cloudASNs[rec.AutonomousSystemNumber]; ok {
				result.CloudVendor = vendor
			}
		}
	}
}

// GetGeoCountry retrieves the ISO country code from Fiber locals.
func GetGeoCountry(c *fiber.Ctx) string {
	if v, ok := c.Locals("country").(string); ok {
		return v
	}
	return "XX"
}

// GetGeoASN retrieves the ASN from Fiber locals.
func GetGeoASN(c *fiber.Ctx) uint {
	if v, ok := c.Locals("asn").(uint); ok {
		return v
	}
	return 0
}

// GetGeoOrgName retrieves the ASN org name from Fiber locals.
func GetGeoOrgName(c *fiber.Ctx) string {
	if v, ok := c.Locals("org_name").(string); ok {
		return v
	}
	return "unknown"
}

// GetCloudVendor retrieves the cloud vendor slug from Fiber locals.
func GetCloudVendor(c *fiber.Ctx) string {
	if v, ok := c.Locals("cloud_vendor").(string); ok {
		return v
	}
	return "unknown"
}

// LoadGeoLite2 opens both the City and ASN MaxMind MMDB files.
// It returns nil gracefully if either file is missing, relying on warnOnce in the middleware.
func LoadGeoLite2(cityPath string) *GeoDBs {
	// Try both city and ASN databases.
	// ASN DB path is conventionally the city path with "-ASN" suffix.
	asnPath := cityPath

	// Attempt to derive ASN path if city path contains "City"
	import_path := cityPath
	_ = import_path

	cityDB, err := maxminddb.Open(cityPath)
	if err != nil {
		slog.Warn("geo.LoadGeoLite2: city database not found", "path", cityPath, "error", err)
		return nil
	}

	// Try ASN DB at same dir with different name
	asnDB, err := maxminddb.Open(asnPath)
	if err != nil {
		// City only — ASN lookups will be skipped
		slog.Warn("geo.LoadGeoLite2: ASN database not found, vendor detection disabled", "error", err)
		return &GeoDBs{City: cityDB, ASN: nil}
	}

	return &GeoDBs{City: cityDB, ASN: asnDB}
}
