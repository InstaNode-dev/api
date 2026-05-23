package storage

import "instant.dev/common/storageprovider"

// NewWithImpl builds a Provider around an already-constructed
// StorageCredentialProvider impl. It exists so tests (in other packages) can
// inject a hermetic fake impl — e.g. one whose Capabilities report
// PrefixScopedKeys=true and whose IssueTenantCredentials is pure computation —
// to drive the prefix-scoped credential path of the storage handler without a
// live MinIO / S3 / R2 backend.
//
// Production code never calls this; it constructs the impl via NewWithBackend /
// NewFromConfig (which route through common's Factory). The function lives in a
// non-test file because callers in the handlers_test package need it at compile
// time.
func NewWithImpl(impl storageprovider.StorageCredentialProvider, bucketName, publicEndpoint, endpoint string, useTLS bool) *Provider {
	return &Provider{
		impl:       impl,
		backendTag: tagForStorageProvider(storageprovider.NormalizeBackend(impl.Name())),
		bucketName: bucketName,
		publicURL:  publicEndpoint,
		endpoint:   endpoint,
		useTLS:     useTLS,
	}
}
