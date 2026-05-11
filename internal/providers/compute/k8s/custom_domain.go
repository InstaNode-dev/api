package k8s

// custom_domain.go — k8s helpers for binding a customer-owned hostname to a
// stack service. Lives alongside the stack provider so the underlying
// clientset is reused without additional plumbing.
//
// Two callers expect to use these:
//
//   1. The custom-domain handler, after TXT verification succeeds, calls
//      EnsureCustomDomainIngress to create / update an Ingress for the
//      hostname. cert-manager picks up the cluster-issuer annotation and
//      issues a real cert.
//
//   2. The same handler polls CertificateReady to surface "cert is live yet?"
//      to the dashboard / API caller. cert-manager Certificates are CRDs, so
//      we use a dynamic client (no need to vendor cert-manager Go types).
//
// The Ingress secretName follows a deterministic pattern so re-creating the
// row produces an idempotent k8s update, not a duplicate.

import (
	"context"
	"fmt"
	"os"
	"strings"

	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// certManagerCertificateGVR is the GroupVersionResource for
// cert-manager.io/v1 Certificate. Held as a package-level var so tests can
// override (e.g. point at a fake CRD).
var certManagerCertificateGVR = schema.GroupVersionResource{
	Group:    "cert-manager.io",
	Version:  "v1",
	Resource: "certificates",
}

// sanitizeHostname turns a customer-supplied hostname into a DNS-1123 fragment
// safe for use as a k8s resource name suffix. ASCII letters / digits stay,
// dots become dashes, everything else collapses to a dash.
//
// Example: "App.Acme.com" -> "app-acme-com"
func sanitizeHostname(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	out := make([]byte, 0, len(host))
	for i := 0; i < len(host); i++ {
		c := host[i]
		switch {
		case c >= 'a' && c <= 'z',
			c >= '0' && c <= '9':
			out = append(out, c)
		default:
			out = append(out, '-')
		}
	}
	// Collapse repeats and trim leading / trailing dashes.
	collapsed := make([]byte, 0, len(out))
	prevDash := true // treat start as if previous was a dash (trim leading)
	for _, c := range out {
		if c == '-' {
			if prevDash {
				continue
			}
			prevDash = true
		} else {
			prevDash = false
		}
		collapsed = append(collapsed, c)
	}
	for len(collapsed) > 0 && collapsed[len(collapsed)-1] == '-' {
		collapsed = collapsed[:len(collapsed)-1]
	}
	return string(collapsed)
}

// CustomDomainIngressName returns the k8s Ingress name for a custom-domain
// binding. The base service name is included so a single stack service can
// host more than one hostname.
func CustomDomainIngressName(svcName, hostname string) string {
	return "cdom-" + svcName + "-" + sanitizeHostname(hostname)
}

// CustomDomainTLSSecretName returns the k8s Secret name where cert-manager
// will store the issued cert chain. The exported name is also the value of
// `tls.secretName` in the Ingress spec.
func CustomDomainTLSSecretName(hostname string) string {
	return "cdom-" + sanitizeHostname(hostname) + "-tls"
}

// EnsureCustomDomainIngress creates (or updates) an Ingress + cert-manager
// Certificate that routes https://hostname to (serviceName:servicePort) inside
// stackNamespace. Returns the Certificate resource name so callers can poll
// its readiness via CertificateReady.
//
// The Ingress is named per-(service, hostname) so a single namespace can hold
// the original deployment Ingress (`<slug>.deployment.instanode.dev`) plus
// any number of custom-domain Ingresses without colliding.
func (p *K8sStackProvider) EnsureCustomDomainIngress(
	ctx context.Context,
	stackNamespace, hostname, serviceName string,
	servicePort int,
) (string, error) {
	if hostname == "" {
		return "", fmt.Errorf("k8s.EnsureCustomDomainIngress: hostname is required")
	}
	if serviceName == "" {
		return "", fmt.Errorf("k8s.EnsureCustomDomainIngress: serviceName is required")
	}
	if servicePort == 0 {
		servicePort = 8080
	}

	hostname = strings.ToLower(strings.TrimSpace(hostname))
	ingressName := CustomDomainIngressName(serviceName, hostname)
	secretName := CustomDomainTLSSecretName(hostname)
	pathType := networkingv1.PathTypePrefix

	// cert-manager wiring: HTTP-01 by default, overridable via CERT_ISSUER.
	// The Certificate is created implicitly by cert-manager when it sees an
	// Ingress with the cluster-issuer annotation + a TLS section pointing at
	// a missing Secret. We do NOT manually CRUD the Certificate CRD here.
	certIssuer := os.Getenv("CERT_ISSUER")
	if certIssuer == "" {
		certIssuer = "letsencrypt-http01"
	}

	annotations := map[string]string{
		"cert-manager.io/cluster-issuer": certIssuer,
	}

	desired := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:        ingressName,
			Namespace:   stackNamespace,
			Annotations: annotations,
			Labels: map[string]string{
				"app":                       serviceName,
				"instant.dev/custom-domain": "true",
			},
		},
		Spec: networkingv1.IngressSpec{
			TLS: []networkingv1.IngressTLS{{
				Hosts:      []string{hostname},
				SecretName: secretName,
			}},
			Rules: []networkingv1.IngressRule{{
				Host: hostname,
				IngressRuleValue: networkingv1.IngressRuleValue{
					HTTP: &networkingv1.HTTPIngressRuleValue{
						Paths: []networkingv1.HTTPIngressPath{{
							Path:     "/",
							PathType: &pathType,
							Backend: networkingv1.IngressBackend{
								Service: &networkingv1.IngressServiceBackend{
									Name: serviceName,
									Port: networkingv1.ServiceBackendPort{
										Number: int32(servicePort),
									},
								},
							},
						}},
					},
				},
			}},
		},
	}

	existing, err := p.clientset.NetworkingV1().Ingresses(stackNamespace).Get(ctx, ingressName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		if _, createErr := p.clientset.NetworkingV1().Ingresses(stackNamespace).Create(ctx, desired, metav1.CreateOptions{}); createErr != nil {
			if apierrors.IsForbidden(createErr) {
				return "", fmt.Errorf("k8s.EnsureCustomDomainIngress: RBAC forbidden creating ingress %q in %q: %w", ingressName, stackNamespace, createErr)
			}
			return "", fmt.Errorf("k8s.EnsureCustomDomainIngress: create ingress %q: %w", ingressName, createErr)
		}
		// cert-manager names the Certificate after the TLS secret name when
		// Ingress shim creates it. Return the secret name as the cert name.
		return secretName, nil
	}
	if err != nil {
		return "", fmt.Errorf("k8s.EnsureCustomDomainIngress: get ingress %q: %w", ingressName, err)
	}

	// Update existing — preserve resourceVersion + apply our spec/annotations.
	existing.Spec = desired.Spec
	existing.Annotations = desired.Annotations
	if existing.Labels == nil {
		existing.Labels = map[string]string{}
	}
	for k, v := range desired.Labels {
		existing.Labels[k] = v
	}
	if _, err := p.clientset.NetworkingV1().Ingresses(stackNamespace).Update(ctx, existing, metav1.UpdateOptions{}); err != nil {
		return "", fmt.Errorf("k8s.EnsureCustomDomainIngress: update ingress %q: %w", ingressName, err)
	}
	return secretName, nil
}

// DeleteCustomDomainIngress removes the Ingress and (best-effort) the TLS
// Secret for a custom-domain binding. cert-manager removes its Certificate
// CRD when the owning Ingress goes away in shim mode.
//
// Best-effort: not-found errors are swallowed so the caller can mark the
// row deleted in the DB even after a partial teardown.
func (p *K8sStackProvider) DeleteCustomDomainIngress(
	ctx context.Context,
	stackNamespace, hostname, serviceName string,
) error {
	hostname = strings.ToLower(strings.TrimSpace(hostname))
	ingressName := CustomDomainIngressName(serviceName, hostname)
	secretName := CustomDomainTLSSecretName(hostname)

	if err := p.clientset.NetworkingV1().Ingresses(stackNamespace).Delete(ctx, ingressName, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("k8s.DeleteCustomDomainIngress: delete ingress %q: %w", ingressName, err)
	}
	// TLS secret cleanup is best-effort — cert-manager's Ingress shim usually
	// owns it, but on some installs it lingers.
	_ = p.clientset.CoreV1().Secrets(stackNamespace).Delete(ctx, secretName, metav1.DeleteOptions{})
	return nil
}

// CertificateReady returns whether the cert-manager Certificate named
// `certName` in `namespace` has condition Ready=True. The second return
// value is the human-readable message attached to the condition (used to
// surface stuck issuance to the caller).
//
// Uses the dynamic client so the API binary does not vendor cert-manager Go
// types — those would pull in their entire CRD module just for one field.
func (p *K8sStackProvider) CertificateReady(
	ctx context.Context,
	namespace, certName string,
) (bool, string, error) {
	dyn, err := newDynamicClient()
	if err != nil {
		return false, "", fmt.Errorf("k8s.CertificateReady: dynamic client: %w", err)
	}
	obj, err := dyn.Resource(certManagerCertificateGVR).Namespace(namespace).Get(ctx, certName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			// cert-manager hasn't created the Certificate yet (shim races
			// Ingress reconcile). Treat as not-ready, no error.
			return false, "Certificate not yet created by cert-manager", nil
		}
		return false, "", fmt.Errorf("k8s.CertificateReady: get certificate %q: %w", certName, err)
	}

	// Walk status.conditions for the Ready entry.
	conds, found, err := unstructuredSlice(obj.Object, "status", "conditions")
	if err != nil || !found {
		return false, "Certificate has no status conditions yet", nil
	}
	for _, c := range conds {
		condMap, ok := c.(map[string]interface{})
		if !ok {
			continue
		}
		condType, _ := condMap["type"].(string)
		if condType != "Ready" {
			continue
		}
		condStatus, _ := condMap["status"].(string)
		condMsg, _ := condMap["message"].(string)
		return condStatus == "True", condMsg, nil
	}
	return false, "Certificate Ready condition not yet present", nil
}

// newDynamicClient builds a dynamic.Interface using the same in-cluster /
// kubeconfig fallback chain as newClientset above. Kept as a free function
// so callers can construct ad-hoc clients without holding a K8sProvider.
func newDynamicClient() (dynamic.Interface, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		cfg, err = clientcmd.BuildConfigFromFlags("", clientcmd.RecommendedHomeFile)
		if err != nil {
			return nil, fmt.Errorf("k8s dynamic config: %w", err)
		}
	}
	return dynamic.NewForConfig(cfg)
}

// unstructuredSlice digs out a []interface{} at the given nested map path.
// Mirrors the single helper from k8s.io/apimachinery/pkg/apis/meta/v1/unstructured
// but without the import — we only need it once.
func unstructuredSlice(obj map[string]interface{}, path ...string) ([]interface{}, bool, error) {
	cur := interface{}(obj)
	for _, key := range path {
		m, ok := cur.(map[string]interface{})
		if !ok {
			return nil, false, fmt.Errorf("path %v: expected map at %q", path, key)
		}
		next, ok := m[key]
		if !ok {
			return nil, false, nil
		}
		cur = next
	}
	out, ok := cur.([]interface{})
	if !ok {
		return nil, false, fmt.Errorf("path %v: expected slice at end", path)
	}
	return out, true, nil
}
