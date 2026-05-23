package handlers_test

// logs_streamerr_twinlogs_test.go — covers the LAST uncovered arm of
// LogsHandler.ResourceLogs (logs.go:230-236): req.Stream(streamCtx) returns an
// error, so the handler logs stream_failed, cancels the background context, and
// returns 503 stream_failed.
//
// The vanilla k8s fake clientset's GetLogs always returns a request whose
// Stream succeeds with a canned "fake logs" body, so the error arm is
// unreachable through it. We wrap the fake in a thin kubernetes.Interface that
// delegates everything (so pod LIST still succeeds and we reach the GetLogs
// step) EXCEPT pod GetLogs, which we override to return a request backed by a
// rest/fake.RESTClient whose Err is set — making Stream(ctx) fail
// deterministically.

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/kubernetes/scheme"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	restclient "k8s.io/client-go/rest"
	restfake "k8s.io/client-go/rest/fake"

	"instant.dev/internal/handlers"
	"instant.dev/internal/testhelpers"

	"errors"
)

// streamErrClientset wraps a real fake clientset; only pod GetLogs is altered so
// its returned request fails on Stream.
type streamErrClientset struct {
	kubernetes.Interface
}

func (c *streamErrClientset) CoreV1() typedcorev1.CoreV1Interface {
	return &streamErrCoreV1{c.Interface.CoreV1()}
}

type streamErrCoreV1 struct {
	typedcorev1.CoreV1Interface
}

func (c *streamErrCoreV1) Pods(namespace string) typedcorev1.PodInterface {
	return &streamErrPods{c.CoreV1Interface.Pods(namespace)}
}

type streamErrPods struct {
	typedcorev1.PodInterface
}

// GetLogs returns a request whose Stream(ctx) errors — backed by a
// rest/fake.RESTClient with Err set.
func (p *streamErrPods) GetLogs(name string, opts *corev1.PodLogOptions) *restclient.Request {
	rc := &restfake.RESTClient{
		NegotiatedSerializer: scheme.Codecs.WithoutConversion(),
		GroupVersion:         schema.GroupVersion{Version: "v1"},
		Err:                  errors.New("log stream upstream unavailable"),
	}
	return rc.Request()
}

func TestLogs_StreamFailed_503(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	const ns = "ns-stream-err"
	// A matching pod so the LIST step succeeds and we reach GetLogs/Stream.
	base := k8sfake.NewSimpleClientset(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "postgres-0",
			Namespace: ns,
			Labels:    map[string]string{"app": "postgres"},
		},
	})
	cs := &streamErrClientset{Interface: base}

	h := handlers.NewLogsHandler(db)
	h.SetClientset(cs)
	app := logsTestApp(t, db, h)

	token := seedLogsResource(t, db, "postgres", "growth", "active", ns)
	resp := logsGet(t, app, token, "")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}
