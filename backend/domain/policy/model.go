package policy

import (
	"hash/fnv"
	"sort"
	"strings"

	flowpb "github.com/cilium/cilium/api/v1/flow"

	pbUi "github.com/cilium/hubble-ui/backend/proto/ui"
)

const (
	// Labels below use the same encoding Hubble uses in flows, so that the
	// frontend recognizes namespaces, reserved identities and app names.
	namespaceLabelKey        = "k8s:io.kubernetes.pod.namespace"
	namespaceMetaLabelPrefix = "k8s:io.cilium.k8s.namespace.labels."
	clusterLabelKey          = "k8s:io.cilium.k8s.policy.cluster"
	reservedLabelPrefix      = "reserved:"

	// anyPeerEntity is the entity a rule matches when it has L4 constraints
	// but no L3 ones.
	anyPeerEntity = "all"

	workloadKindSelector = "Selector"
	workloadKindService  = "Service"
	workloadKindCIDR     = "CIDR"
	workloadKindGroup    = "Group"
)

// peer is one side of an access, described the same way Hubble describes a
// service so that the frontend can draw it with an ordinary service map card.
type peer struct {
	labels    []string
	namespace string
	dnsNames  []string
	workloads []*flowpb.Workload
}

type portProto struct {
	port  uint32
	proto pbUi.IPProtocol
}

// edge is one allowed or denied access between a subject and a peer. Ingress
// edges go from the peer to the subject, egress edges the other way around.
type edge struct {
	peer    *peer
	ports   []portProto
	ingress bool
	deny    bool
	auth    flowpb.AuthType
}

// subject is a set of endpoints selected by a policy together with the
// accesses that policy grants or denies them.
type subject struct {
	self               *peer
	ingressDefaultDeny bool
	egressDefaultDeny  bool
	edges              []*edge
}

// addEdges appends one edge per peer. A rule without peers matches nothing
// unless it constrains L4, in which case it matches any peer on those ports.
// A rule without ports matches all ports.
func (s *subject) addEdges(
	peers []*peer,
	ports []portProto,
	hasL4 bool,
	ingress, deny bool,
	auth flowpb.AuthType,
) {
	if len(peers) == 0 {
		if !hasL4 {
			return
		}

		peers = []*peer{newEntityPeer(anyPeerEntity)}
	}

	if len(ports) == 0 {
		ports = allPorts()
	}

	for _, p := range peers {
		s.edges = append(s.edges, &edge{
			peer:    p,
			ports:   ports,
			ingress: ingress,
			deny:    deny,
			auth:    auth,
		})
	}
}

func allPorts() []portProto {
	return []portProto{{port: 0, proto: pbUi.IPProtocol_UNKNOWN_IP_PROTOCOL}}
}

// key identifies equal peers across policies so that they share one card.
func (p *peer) key() string {
	parts := []string{p.namespace, strings.Join(p.labels, ",")}

	if len(p.dnsNames) > 0 {
		parts = append(parts, "dns="+strings.Join(p.dnsNames, ","))
	}

	for _, wl := range p.workloads {
		parts = append(parts, wl.GetKind()+"="+wl.GetName())
	}

	return strings.Join(parts, "|")
}

// appNameLabelKeys are the labels the frontend titles a card by, in the same
// order of preference, so that Service.Name matches what gets rendered.
var appNameLabelKeys = []string{
	"k8s:app",
	"k8s:name",
	"k8s:functionname",
	"k8s:k8s-app",
	"k8s:app.kubernetes.io/name",
}

func (p *peer) caption() string {
	if len(p.dnsNames) > 0 {
		return p.dnsNames[0]
	}

	for _, key := range appNameLabelKeys {
		for _, lbl := range p.labels {
			if value, ok := strings.CutPrefix(lbl, key+"="); ok {
				return value
			}
		}
	}

	for _, lbl := range p.labels {
		if strings.HasPrefix(lbl, reservedLabelPrefix) {
			return strings.TrimPrefix(lbl, reservedLabelPrefix)
		}
	}

	for _, wl := range p.workloads {
		if wl.GetName() != "" {
			return wl.GetName()
		}
	}

	return "unknown"
}

// newPodsPeer describes pods matched by a label selector. The compact
// selector is attached as a workload so that a card without app-like labels
// still gets a readable title.
func newPodsPeer(labels []string, namespace string) *peer {
	selector := []string{}
	for _, lbl := range labels {
		if strings.HasPrefix(lbl, namespaceLabelKey+"=") {
			continue
		}

		selector = append(selector, strings.TrimPrefix(lbl, "k8s:"))
	}

	name := "any pod"
	if len(selector) > 0 {
		name = strings.Join(selector, ",")
	}

	return &peer{
		labels:    sortedCopy(labels),
		namespace: namespace,
		workloads: []*flowpb.Workload{{Kind: workloadKindSelector, Name: name}},
	}
}

func newEntityPeer(entity string) *peer {
	return &peer{labels: []string{reservedLabelPrefix + entity}}
}

// newCIDRPeer keeps the CIDR in dnsNames on purpose: the frontend titles world
// cards by their first DNS name, which is exactly how a CIDR should show up.
func newCIDRPeer(cidr string) *peer {
	return &peer{
		labels:    []string{reservedLabelPrefix + "world", "cidr:" + cidr},
		dnsNames:  []string{cidr},
		workloads: []*flowpb.Workload{{Kind: workloadKindCIDR, Name: cidr}},
	}
}

func newFQDNPeer(pattern string) *peer {
	return &peer{
		labels:   []string{reservedLabelPrefix + "world", "fqdn:" + pattern},
		dnsNames: []string{pattern},
	}
}

func newServicePeer(name, namespace string) *peer {
	return &peer{
		labels:    []string{namespaceLabelKey + "=" + namespace},
		namespace: namespace,
		workloads: []*flowpb.Workload{{Kind: workloadKindService, Name: name}},
	}
}

func newGroupPeer(description string) *peer {
	return &peer{
		labels:    []string{reservedLabelPrefix + "world"},
		dnsNames:  []string{description},
		workloads: []*flowpb.Workload{{Kind: workloadKindGroup, Name: description}},
	}
}

func sortedCopy(strs []string) []string {
	res := make([]string, len(strs))
	copy(res, strs)
	sort.Strings(res)

	return res
}

// stableIdentity derives a positive, deterministic identity from a card id.
// The frontend expects every card to have a non-zero identity.
func stableIdentity(id string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(id))

	return h.Sum32()%(1<<31-1) + 1
}
