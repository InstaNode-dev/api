package k8s

// build_context.go — MinIO-backed kaniko build-context delivery.
//
// The legacy path stores the tarball in a k8s Secret which etcd caps at ~1 MiB.
// That cap routinely defeats agents shipping anything more than a Dockerfile +
// a tiny entrypoint. This file uploads the tarball to MinIO and hands kaniko a
// short-lived presigned HTTP URL — avoiding the AWS-SDK-v2 path-style quirks
// that broke the s3:// approach (vhost-style hostname resolution against
// in-cluster MinIO DNS).
//
// Practical new cap = the multipart limit enforced in the deploy handler
// (currently 50 MiB) instead of the etcd object-size limit.

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// presignTTL is the lifetime of the kaniko-facing context URL. Short enough
// that a leaked link expires before it matters; long enough that a slow
// kaniko fetch finishes. Kaniko builds typically take 30s–3min on the
// provisioned build pod (250m CPU); 30 min is safe.
const presignTTL = 30 * time.Minute

// uploadBuildContext writes the tarball to MinIO and returns:
//   - contextURL: a presigned HTTPS-style URL kaniko reads via --context=<url>
//   - objectKey: the bucket-relative key, so the caller can delete it post-build
//
// Returns ("", "", nil) when buildCtx is unconfigured — caller must fall back
// to the legacy Secret-based delivery.
//
// Why presigned-HTTP instead of s3://: kaniko v1.23 ships AWS SDK v2 which
// resolves S3 endpoints in vhost style by default. The env-only path-style
// switch (S3_FORCE_PATH_STYLE) was an SDK v1 knob and is silently ignored;
// AWS SDK v2 only honours an UsePathStyle option set in code, which we cannot
// inject. Generating a presigned URL on our side sidesteps the whole AWS-SDK
// path/vhost decision: kaniko receives a plain HTTP GET URL.
func (p *K8sProvider) uploadBuildContext(ctx context.Context, appID string, tarball []byte) (contextURL, objectKey string, err error) {
	if p.buildCtx.Endpoint == "" {
		return "", "", nil
	}
	client, err := minio.New(p.buildCtx.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(p.buildCtx.AccessKey, p.buildCtx.SecretKey, ""),
		Secure: p.buildCtx.UseSSL,
	})
	if err != nil {
		return "", "", fmt.Errorf("uploadBuildContext: minio client: %w", err)
	}

	// Ensure the bucket exists. Idempotent; we treat already-exists as success.
	exists, err := client.BucketExists(ctx, p.buildCtx.BucketName)
	if err != nil {
		return "", "", fmt.Errorf("uploadBuildContext: bucket exists check: %w", err)
	}
	if !exists {
		if err := client.MakeBucket(ctx, p.buildCtx.BucketName, minio.MakeBucketOptions{}); err != nil {
			return "", "", fmt.Errorf("uploadBuildContext: make bucket %q: %w", p.buildCtx.BucketName, err)
		}
	}

	// Object key includes a UTC timestamp so concurrent redeploys of the same
	// app don't collide; old keys are cleaned up by a TTL job (not in scope here).
	objectKey = fmt.Sprintf("%s/%s.tar.gz", appID, time.Now().UTC().Format("20060102T150405Z"))

	_, err = client.PutObject(ctx, p.buildCtx.BucketName, objectKey,
		bytes.NewReader(tarball), int64(len(tarball)),
		minio.PutObjectOptions{ContentType: "application/gzip"},
	)
	if err != nil {
		return "", "", fmt.Errorf("uploadBuildContext: put object: %w", err)
	}

	presignedURL, err := client.PresignedGetObject(ctx, p.buildCtx.BucketName, objectKey, presignTTL, url.Values{})
	if err != nil {
		return "", "", fmt.Errorf("uploadBuildContext: presign get: %w", err)
	}
	return presignedURL.String(), objectKey, nil
}
