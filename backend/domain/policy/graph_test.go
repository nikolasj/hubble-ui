package policy

import (
	"io"
	"log/slog"
	"strings"
	"testing"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	networkingv1 "k8s.io/api/networking/v1"
	"sigs.k8s.io/yaml"

	pbUi "github.com/cilium/hubble-ui/backend/proto/ui"
)

const frontendCNP = `
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: frontend
  namespace: demo
  uid: 11111111-1111-1111-1111-111111111111
  annotations:
    kubectl.kubernetes.io/last-applied-configuration: '{"big": "blob"}'
spec:
  description: Frontend accepts web traffic and talks to the backend
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
  egress:
    - toEndpoints:
        - matchLabels:
            app: backend
      toPorts:
        - ports:
            - port: "8080"
              protocol: TCP
      authentication:
        mode: required
    - toFQDNs:
        - matchName: api.github.com
      toPorts:
        - ports:
            - port: "443"
              protocol: TCP
    - toEndpoints:
        - matchLabels:
            k8s-app: kube-dns
            k8s:io.kubernetes.pod.namespace: kube-system
      toPorts:
        - ports:
            - port: "53"
              protocol: UDP
  egressDeny:
    - toCIDR:
        - 169.254.169.254/32
`

const backendCNP = `
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: backend
  namespace: demo
spec:
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
`

const denyAllEgressCNP = `
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: cron-deny-all-egress
  namespace: demo
spec:
  endpointSelector:
    matchLabels:
      app: cron
  egress:
    - {}
`

const l4OnlyCNP = `
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: metrics
  namespace: demo
spec:
  endpointSelector:
    matchLabels:
      app: backend
  ingress:
    - toPorts:
        - ports:
            - port: "9090"
              protocol: TCP
`

const dnsCCNP = `
apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
metadata:
  name: allow-dns
spec:
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
    - toEntities:
        - kube-apiserver
`

const otherNamespaceCCNP = `
apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
metadata:
  name: other-namespace-only
spec:
  endpointSelector:
    matchLabels:
      k8s:io.kubernetes.pod.namespace: other
  ingress:
    - fromEntities:
        - world
`

const webKNP = `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: web
  namespace: demo
spec:
  podSelector:
    matchLabels:
      app: web
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              team: platform
          podSelector:
            matchLabels:
              role: ingress
        - ipBlock:
            cidr: 10.0.0.0/8
      ports:
        - port: 80
`

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func parseCNP(t *testing.T, doc string) *Object {
	t.Helper()

	cnp := new(ciliumv2.CiliumNetworkPolicy)
	if err := yaml.Unmarshal([]byte(doc), cnp); err != nil {
		t.Fatalf("failed to parse CNP fixture: %v", err)
	}

	return FromCiliumNetworkPolicy(testLogger(), cnp)
}

func parseCCNP(t *testing.T, doc string) *Object {
	t.Helper()

	ccnp := new(ciliumv2.CiliumClusterwideNetworkPolicy)
	if err := yaml.Unmarshal([]byte(doc), ccnp); err != nil {
		t.Fatalf("failed to parse CCNP fixture: %v", err)
	}

	return FromCiliumClusterwideNetworkPolicy(testLogger(), ccnp)
}

func parseKNP(t *testing.T, doc string) *Object {
	t.Helper()

	np := new(networkingv1.NetworkPolicy)
	if err := yaml.Unmarshal([]byte(doc), np); err != nil {
		t.Fatalf("failed to parse NetworkPolicy fixture: %v", err)
	}

	return FromNetworkPolicy(np)
}

func serviceByCaption(t *testing.T, g *Graph, caption string) *pbUi.Service {
	t.Helper()

	for _, svc := range g.Services {
		if svc.GetName() == caption {
			return svc
		}
	}

	t.Fatalf("service %q is not in the graph, have: %s", caption, captions(g))

	return nil
}

func captions(g *Graph) string {
	names := []string{}
	for _, svc := range g.Services {
		names = append(names, svc.GetName())
	}

	return strings.Join(names, ", ")
}

func linkBetween(t *testing.T, g *Graph, src, dst *pbUi.Service, port uint32) *pbUi.ServiceLink {
	t.Helper()

	for _, link := range g.Links {
		if link.GetSourceId() == src.GetId() &&
			link.GetDestinationId() == dst.GetId() &&
			link.GetDestinationPort() == port {
			return link
		}
	}

	t.Fatalf("no link %s -> %s:%d", src.GetName(), dst.GetName(), port)

	return nil
}

func hasLabel(svc *pbUi.Service, label string) bool {
	for _, lbl := range svc.GetLabels() {
		if lbl == label {
			return true
		}
	}

	return false
}

func TestCiliumNetworkPolicyObject(t *testing.T) {
	obj := parseCNP(t, frontendCNP)

	if obj.Kind != KindCiliumNetworkPolicy || obj.Name != "frontend" || obj.Namespace != "demo" {
		t.Fatalf("unexpected object identity: %+v", obj)
	}

	if obj.Description != "Frontend accepts web traffic and talks to the backend" {
		t.Errorf("unexpected description: %q", obj.Description)
	}

	if !strings.Contains(obj.YAML, "kind: CiliumNetworkPolicy") ||
		!strings.Contains(obj.YAML, "apiVersion: cilium.io/v2") {
		t.Errorf("YAML lacks type meta:\n%s", obj.YAML)
	}

	if strings.Contains(obj.YAML, "last-applied-configuration") {
		t.Errorf("YAML still carries the kubectl annotation:\n%s", obj.YAML)
	}

	if len(obj.subjects) != 1 {
		t.Fatalf("expected one subject, got %d", len(obj.subjects))
	}

	subj := obj.subjects[0]
	if subj.self.namespace != "demo" {
		t.Errorf("subject namespace = %q, want demo", subj.self.namespace)
	}

	if !subj.ingressDefaultDeny || !subj.egressDefaultDeny {
		t.Errorf("expected default deny in both directions: %+v", subj)
	}
}

func TestBuildGraphFromCiliumNetworkPolicy(t *testing.T) {
	g := BuildGraph("demo", []*Object{parseCNP(t, frontendCNP)})

	if len(g.Services) != 6 {
		t.Fatalf("expected 6 services, got %d: %s", len(g.Services), captions(g))
	}

	if len(g.Links) != 5 {
		t.Fatalf("expected 5 links, got %d", len(g.Links))
	}

	frontend := serviceByCaption(t, g, "frontend")
	if frontend.GetNamespace() != "demo" ||
		!hasLabel(frontend, "k8s:app=frontend") ||
		!hasLabel(frontend, "k8s:io.kubernetes.pod.namespace=demo") {
		t.Errorf("subject card is not scoped to the namespace: %+v", frontend)
	}

	if !frontend.GetIngressPolicyEnforced() || !frontend.GetEgressPolicyEnforced() {
		t.Errorf("subject card should carry default deny flags: %+v", frontend)
	}

	world := serviceByCaption(t, g, "world")
	if !hasLabel(world, "reserved:world") {
		t.Errorf("world entity card lacks the reserved label: %+v", world)
	}

	ingress := linkBetween(t, g, world, frontend, 443)
	if ingress.GetVerdict() != flowpb.Verdict_FORWARDED || ingress.GetIpProtocol() != pbUi.IPProtocol_TCP {
		t.Errorf("unexpected ingress link: %+v", ingress)
	}

	backend := serviceByCaption(t, g, "backend")
	if backend.GetNamespace() != "demo" {
		t.Errorf("peer in the same namespace must inherit it: %+v", backend)
	}

	toBackend := linkBetween(t, g, frontend, backend, 8080)
	if toBackend.GetAuthType() != flowpb.AuthType_SPIRE {
		t.Errorf("required authentication must show up as SPIRE: %+v", toBackend)
	}

	github := serviceByCaption(t, g, "api.github.com")
	if !hasLabel(github, "reserved:world") || github.GetDnsNames()[0] != "api.github.com" {
		t.Errorf("FQDN peer must be a world card titled by the name: %+v", github)
	}

	kubeDNS := serviceByCaption(t, g, "kube-dns")
	if kubeDNS.GetNamespace() != "kube-system" {
		t.Errorf("explicit namespace in a selector must be kept: %+v", kubeDNS)
	}

	if hasLabel(kubeDNS, "k8s:io.kubernetes.pod.namespace=demo") {
		t.Errorf("policy namespace must not be injected next to an explicit one: %+v", kubeDNS)
	}

	dns := linkBetween(t, g, frontend, kubeDNS, 53)
	if dns.GetIpProtocol() != pbUi.IPProtocol_UDP {
		t.Errorf("unexpected protocol for dns link: %+v", dns)
	}

	metadata := serviceByCaption(t, g, "169.254.169.254/32")
	deny := linkBetween(t, g, frontend, metadata, 0)
	if deny.GetVerdict() != flowpb.Verdict_DROPPED {
		t.Errorf("deny rule must produce a dropped link: %+v", deny)
	}

	key := "CiliumNetworkPolicy/demo/frontend"
	if len(g.ServiceIDs[key]) != 6 || len(g.LinkIDs[key]) != 5 {
		t.Errorf("policy should own every card and link: %v %v", g.ServiceIDs[key], g.LinkIDs[key])
	}
}

func TestBuildGraphSharesCardsBetweenPolicies(t *testing.T) {
	g := BuildGraph("demo", []*Object{parseCNP(t, frontendCNP), parseCNP(t, backendCNP)})

	backends := 0
	for _, svc := range g.Services {
		if svc.GetName() == "backend" {
			backends++
		}
	}

	if backends != 1 {
		t.Fatalf("the same selector must produce one card, got %d", backends)
	}

	identities := map[uint32]bool{}
	for _, svc := range g.Services {
		if svc.GetIdentity() == 0 || identities[svc.GetIdentity()] {
			t.Errorf("identity must be unique and non-zero: %+v", svc)
		}

		identities[svc.GetIdentity()] = true
	}
}

func TestEmptyRuleOnlyEnablesDefaultDeny(t *testing.T) {
	g := BuildGraph("demo", []*Object{parseCNP(t, denyAllEgressCNP)})

	if len(g.Links) != 0 {
		t.Fatalf("an empty rule matches nothing, got links: %+v", g.Links)
	}

	cron := serviceByCaption(t, g, "cron")
	if !cron.GetEgressPolicyEnforced() || cron.GetIngressPolicyEnforced() {
		t.Errorf("only egress should be default deny: %+v", cron)
	}
}

func TestL4OnlyRuleMatchesAnyPeer(t *testing.T) {
	g := BuildGraph("demo", []*Object{parseCNP(t, l4OnlyCNP)})

	all := serviceByCaption(t, g, "all")
	backend := serviceByCaption(t, g, "backend")
	linkBetween(t, g, all, backend, 9090)
}

func TestClusterwidePolicies(t *testing.T) {
	g := BuildGraph("demo", []*Object{parseCCNP(t, dnsCCNP), parseCCNP(t, otherNamespaceCCNP)})

	anyPod := serviceByCaption(t, g, "any pod")
	if anyPod.GetNamespace() != "demo" || !hasLabel(anyPod, "k8s:io.kubernetes.pod.namespace=demo") {
		t.Errorf("cluster-wide subject must be drawn inside the namespace: %+v", anyPod)
	}

	kubeDNS := serviceByCaption(t, g, "kube-dns")
	linkBetween(t, g, anyPod, kubeDNS, 53)

	apiServer := serviceByCaption(t, g, "kube-apiserver")
	linkBetween(t, g, anyPod, apiServer, 0)

	for _, svc := range g.Services {
		if svc.GetName() == "world" {
			t.Errorf("policy pinned to another namespace must be skipped: %s", captions(g))
		}
	}
}

func TestKubernetesNetworkPolicy(t *testing.T) {
	obj := parseKNP(t, webKNP)
	g := BuildGraph("demo", []*Object{obj})

	web := serviceByCaption(t, g, "web")
	if !web.GetIngressPolicyEnforced() || web.GetEgressPolicyEnforced() {
		t.Errorf("policyTypes: [Ingress] must only enforce ingress: %+v", web)
	}

	var platform *pbUi.Service
	for _, svc := range g.Services {
		if hasLabel(svc, "k8s:io.cilium.k8s.namespace.labels.team=platform") {
			platform = svc
		}
	}

	if platform == nil || !hasLabel(platform, "k8s:role=ingress") || platform.GetNamespace() != "" {
		t.Fatalf("namespace selector peer is wrong: %+v (%s)", platform, captions(g))
	}

	fromPlatform := linkBetween(t, g, platform, web, 80)
	if fromPlatform.GetIpProtocol() != pbUi.IPProtocol_TCP {
		t.Errorf("protocol must default to TCP: %+v", fromPlatform)
	}

	block := serviceByCaption(t, g, "10.0.0.0/8")
	linkBetween(t, g, block, web, 80)

	if !strings.Contains(obj.YAML, "kind: NetworkPolicy") {
		t.Errorf("YAML lacks type meta:\n%s", obj.YAML)
	}
}

func TestSelectorKeyDecoding(t *testing.T) {
	cases := map[string]string{
		"app":                              "k8s:app",
		"any.app":                          "k8s:app",
		"k8s.io.kubernetes.pod.namespace":  "k8s:io.kubernetes.pod.namespace",
		"k8s:io.kubernetes.pod.namespace":  "k8s:io.kubernetes.pod.namespace",
		"reserved.remote-node":             "reserved:remote-node",
		"app.kubernetes.io/name":           "k8s:app.kubernetes.io/name",
		"io.cilium.k8s.namespace.labels.x": "k8s:io.cilium.k8s.namespace.labels.x",
	}

	for in, want := range cases {
		if got := decodeSelectorKey(in); got != want {
			t.Errorf("decodeSelectorKey(%q) = %q, want %q", in, got, want)
		}
	}
}
