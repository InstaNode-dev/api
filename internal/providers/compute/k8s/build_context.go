package k8s

// build_context.go — MinIO-backed kaniko build-context delivery.
//
// The legacy path stores the tarball in a k8s Secret which etcd caps at ~1 MiB.
// That cap routinely defeats agents shipping anything more than a Dockerfile +
// a tiny entrypoint. This file implements the S3 path: upload the tarball
// once via minio-go, then point kaniko at the resulting s3:// URL.
//
// Practical new cap = the multipart limit enforced in the deploy handler
// (currently 50 MiB) instead of the etcd object-size limit.

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// uploadBuildContext writes the tarball to MinIO and returns:
//   - s3URL: the s3://bucket/key URL kaniko's --context flag accepts
//   - objectKey: the bucket-relative key, so the caller can delete it post-build
//
// Returns ("", "", nil) when buildCtx is unconfigured — caller must fall back
// to the legacy Secret-based delivery.
func (p *K8sProvider) uploadBuildContext(ctx context.Context, appID string, tarball []byte) (s3URL, objectKey string, err error) {
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

	s3URL = fmt.Sprintf("s3://%s/%s", p.buildCtx.BucketName, objectKey)
	return s3URL, objectKey, nil
}
