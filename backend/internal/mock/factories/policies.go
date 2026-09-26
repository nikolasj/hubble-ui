package factories

import (
	"fmt"
	"log/slog"
	"strings"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	networkingv1 "k8s.io/api/networking/v1"
	"sigs.k8s.io/yaml"

	"github.com/cilium/hubble-ui/backend/domain/policy"
)

const namespacePlaceholder = "__NS__"

// Fixtures below describe a small shop-like namespace so that the policy view
// can be developed and demoed without a cluster (E2E_TEST_MODE=true).
var mockCiliumNetworkPolicies = []string{`
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: frontend
  namespace: __NS__
  uid: 3f1c6b1e-0001-4b3a-9c1d-000000000001
  resourceVersion: "1001"
spec:
  description: Frontend serves the internet and calls the backend API
  endpointSelector:
    matchLabels:
      app: frontend
  ingress:
    - fromEntities:
        - world
      toPorts:
        - ports:
            - port: "443"
              protocol: TCP
            - port: "80"
              protocol: TCP
  egress:
    - toEndpoints:
        - matchLabels:
            app: backend
      toPorts:
        - ports:
            - port: "8080"
              protocol: TCP
          rules:
            http:
              - method: GET
                path: /api/.*
    - toFQDNs:
        - matchName: api.github.com
      toPorts:
        - ports:
            - port: "443"
              protocol: TCP
`, `
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: backend
  namespace: __NS__
  uid: 3f1c6b1e-0001-4b3a-9c1d-000000000002
  resourceVersion: "1002"
spec:
  description: Backend talks to the database and the Kubernetes API
  endpointSelector:
    matchLabels:
      app: backend
  ingress:
    - fromEndpoints:
        - matchLabels:
            app: frontend
      toPorts:
        - ports:
            - port: "8080"
              protocol: TCP
      authentication:
        mode: required
  egress:
    - toEndpoints:
        - matchLabels:
            app: postgres
            k8s:io.kubernetes.pod.namespace: databases
      toPorts:
        - ports:
            - port: "5432"
              protocol: TCP
    - toEntities:
        - kube-apiserver
  egressDeny:
    - toCIDR:
        - 169.254.169.254/32
`, `
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: cron-deny-all-egress
  namespace: __NS__
  uid: 3f1c6b1e-0001-4b3a-9c1d-000000000003
  resourceVersion: "1003"
spec:
  description: Cron jobs are not allowed to talk to anything
  endpointSelector:
    matchLabels:
      app: cron
  egress:
    - {}
`}

var mockClusterwidePolicies = []string{`
apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
metadata:
  name: allow-dns
  uid: 3f1c6b1e-0002-4b3a-9c1d-000000000001
  resourceVersion: "2001"
spec:
  description: Every pod may resolve names through kube-dns
  endpointSelector: {}
  egress:
    - toEndpoints:
        - matchLabels:
            k8s-app: kube-dns
            k8s:io.kubernetes.pod.namespace: kube-system
      toPorts:
        - ports:
            - port: "53"
              protocol: UDP
          rules:
            dns:
              - matchPattern: "*"
`}

var mockNetworkPolicies = []string{`
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: metrics-scraping
  namespace: __NS__
  uid: 3f1c6b1e-0003-4b3a-9c1d-000000000001
  resourceVersion: "3001"
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: monitoring
          podSelector:
            matchLabels:
              app: prometheus
      ports:
        - port: 9090
          protocol: TCP
`}

func CreatePolicies(log *slog.Logger, namespace string) (*policy.ListResult, error) {
	res := &policy.ListResult{}

	for _, doc := range mockCiliumNetworkPolicies {
		cnp := new(ciliumv2.CiliumNetworkPolicy)
		if err := unmarshalFixture(doc, namespace, cnp); err != nil {
			return nil, err
		}

		res.Objects = append(res.Objects, policy.FromCiliumNetworkPolicy(log, cnp))
	}

	for _, doc := range mockClusterwidePolicies {
		ccnp := new(ciliumv2.CiliumClusterwideNetworkPolicy)
		if err := unmarshalFixture(doc, namespace, ccnp); err != nil {
			return nil, err
		}

		res.Objects = append(res.Objects, policy.FromCiliumClusterwideNetworkPolicy(log, ccnp))
	}

	for _, doc := range mockNetworkPolicies {
		np := new(networkingv1.NetworkPolicy)
		if err := unmarshalFixture(doc, namespace, np); err != nil {
			return nil, err
		}

		res.Objects = append(res.Objects, policy.FromNetworkPolicy(np))
	}

	return res, nil
}

func unmarshalFixture(doc, namespace string, dst any) error {
	doc = strings.ReplaceAll(doc, namespacePlaceholder, namespace)

	if err := yaml.Unmarshal([]byte(doc), dst); err != nil {
		return fmt.Errorf("invalid mock policy fixture: %w", err)
	}

	return nil
}
