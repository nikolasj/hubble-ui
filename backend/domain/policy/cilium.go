package policy

import (
	"sort"
	"strconv"
	"strings"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/policy/api"

	pbUi "github.com/cilium/hubble-ui/backend/proto/ui"
)

// knownLabelSources are the label sources Cilium encodes into selector keys,
// either as "source.key" (after parsing) or "source:key" (as users write them).
var knownLabelSources = map[string]bool{
	"any":       true,
	"k8s":       true,
	"reserved":  true,
	"container": true,
	"cidr":      true,
	"cidrgroup": true,
	"node":      true,
	"fqdn":      true,
	"unspec":    true,
}

func subjectsFromCiliumRules(rules api.Rules) []*subject {
	subjects := make([]*subject, 0, len(rules))

	for _, rule := range rules {
		// Host policies (nodeSelector) are not drawn: the service map has no
		// notion of a node as a subject.
		if rule == nil || rule.EndpointSelector.LabelSelector == nil {
			continue
		}

		labels, namespace := selectorToLabels(rule.EndpointSelector.LabelSelector)
		s := &subject{self: newPodsPeer(labels, namespace)}

		s.ingressDefaultDeny = defaultDenyEnabled(
			rule.EnableDefaultDeny.Ingress,
			len(rule.Ingress) > 0 || len(rule.IngressDeny) > 0,
		)
		s.egressDefaultDeny = defaultDenyEnabled(
			rule.EnableDefaultDeny.Egress,
			len(rule.Egress) > 0 || len(rule.EgressDeny) > 0,
		)

		for i := range rule.Ingress {
			ir := &rule.Ingress[i]
			ports := portsFromRules(ir.ToPorts, ir.ICMPs)
			hasL4 := len(ir.ToPorts) > 0 || len(ir.ICMPs) > 0

			s.addEdges(ingressPeers(&ir.IngressCommonRule), ports, hasL4, true, false, authType(ir.Authentication))
		}

		for i := range rule.IngressDeny {
			ir := &rule.IngressDeny[i]
			ports := portsFromDenyRules(ir.ToPorts, ir.ICMPs)
			hasL4 := len(ir.ToPorts) > 0 || len(ir.ICMPs) > 0

			s.addEdges(ingressPeers(&ir.IngressCommonRule), ports, hasL4, true, true, flowpb.AuthType_DISABLED)
		}

		for i := range rule.Egress {
			er := &rule.Egress[i]
			ports := portsFromRules(er.ToPorts, er.ICMPs)
			hasL4 := len(er.ToPorts) > 0 || len(er.ICMPs) > 0
			peers := egressPeers(&er.EgressCommonRule, er.ToFQDNs, namespace)

			s.addEdges(peers, ports, hasL4, false, false, authType(er.Authentication))
		}

		for i := range rule.EgressDeny {
			er := &rule.EgressDeny[i]
			ports := portsFromDenyRules(er.ToPorts, er.ICMPs)
			hasL4 := len(er.ToPorts) > 0 || len(er.ICMPs) > 0
			peers := egressPeers(&er.EgressCommonRule, nil, namespace)

			s.addEdges(peers, ports, hasL4, false, true, flowpb.AuthType_DISABLED)
		}

		subjects = append(subjects, s)
	}

	return subjects
}

// defaultDenyEnabled mirrors the agent: a direction becomes default-deny as
// soon as a policy has rules for it, unless enableDefaultDeny opts out.
func defaultDenyEnabled(override *bool, hasRules bool) bool {
	if override != nil {
		return *override && hasRules
	}

	return hasRules
}

func ingressPeers(rule *api.IngressCommonRule) []*peer {
	peers := []*peer{}

	for i := range rule.FromEndpoints {
		peers = append(peers, endpointSelectorPeer(&rule.FromEndpoints[i]))
	}

	for i := range rule.FromNodes {
		peers = append(peers, endpointSelectorPeer(&rule.FromNodes[i]))
	}

	for _, entity := range rule.FromEntities {
		peers = append(peers, newEntityPeer(string(entity)))
	}

	for _, cidr := range rule.FromCIDR {
		peers = append(peers, newCIDRPeer(string(cidr)))
	}

	for i := range rule.FromCIDRSet {
		peers = append(peers, cidrRulePeer(&rule.FromCIDRSet[i]))
	}

	for i := range rule.FromGroups {
		peers = append(peers, groupPeer(&rule.FromGroups[i]))
	}

	return peers
}

func egressPeers(rule *api.EgressCommonRule, fqdns api.FQDNSelectorSlice, policyNamespace string) []*peer {
	peers := []*peer{}

	for i := range rule.ToEndpoints {
		peers = append(peers, endpointSelectorPeer(&rule.ToEndpoints[i]))
	}

	for i := range rule.ToNodes {
		peers = append(peers, endpointSelectorPeer(&rule.ToNodes[i]))
	}

	for _, entity := range rule.ToEntities {
		peers = append(peers, newEntityPeer(string(entity)))
	}

	for _, cidr := range rule.ToCIDR {
		peers = append(peers, newCIDRPeer(string(cidr)))
	}

	for i := range rule.ToCIDRSet {
		peers = append(peers, cidrRulePeer(&rule.ToCIDRSet[i]))
	}

	for i := range rule.ToServices {
		peers = append(peers, servicePeer(&rule.ToServices[i], policyNamespace))
	}

	for i := range rule.ToGroups {
		peers = append(peers, groupPeer(&rule.ToGroups[i]))
	}

	for _, fqdn := range fqdns {
		pattern := fqdn.MatchName
		if pattern == "" {
			pattern = fqdn.MatchPattern
		}

		peers = append(peers, newFQDNPeer(pattern))
	}

	return peers
}

func endpointSelectorPeer(es *api.EndpointSelector) *peer {
	labels, namespace := selectorToLabels(es.LabelSelector)

	for _, lbl := range labels {
		if strings.HasPrefix(lbl, reservedLabelPrefix) {
			return &peer{labels: labels, namespace: namespace}
		}
	}

	return newPodsPeer(labels, namespace)
}

func cidrRulePeer(rule *api.CIDRRule) *peer {
	switch {
	case rule.Cidr != "":
		return newCIDRPeer(string(rule.Cidr))
	case rule.CIDRGroupRef != "":
		name := "cidrgroup/" + string(rule.CIDRGroupRef)

		return &peer{
			labels:   []string{reservedLabelPrefix + "world", "cidrgroup:" + string(rule.CIDRGroupRef)},
			dnsNames: []string{name},
		}
	case rule.CIDRGroupSelector.LabelSelector != nil:
		labels, _ := selectorToLabels(rule.CIDRGroupSelector.LabelSelector)
		name := "cidrgroups: " + compactSelector(labels)

		return &peer{
			labels:   append([]string{reservedLabelPrefix + "world"}, labels...),
			dnsNames: []string{name},
		}
	}

	return newEntityPeer("world")
}

func servicePeer(svc *api.Service, policyNamespace string) *peer {
	if svc.K8sService != nil {
		namespace := svc.K8sService.Namespace
		if namespace == "" {
			namespace = policyNamespace
		}

		return newServicePeer(svc.K8sService.ServiceName, namespace)
	}

	if svc.K8sServiceSelector != nil {
		namespace := svc.K8sServiceSelector.Namespace
		if namespace == "" {
			namespace = policyNamespace
		}

		selector := api.EndpointSelector(svc.K8sServiceSelector.Selector)
		labels, _ := selectorToLabels(selector.LabelSelector)

		return &peer{
			labels:    append(labels, namespaceLabelKey+"="+namespace),
			namespace: namespace,
			workloads: []*flowpb.Workload{{
				Kind: workloadKindService,
				Name: "services: " + compactSelector(labels),
			}},
		}
	}

	return newEntityPeer("world")
}

func groupPeer(group *api.Groups) *peer {
	if group.AWS == nil {
		return newGroupPeer("cloud group")
	}

	parts := []string{}
	if group.AWS.Region != "" {
		parts = append(parts, "region="+group.AWS.Region)
	}

	parts = append(parts, group.AWS.SecurityGroupsIds...)
	parts = append(parts, group.AWS.SecurityGroupsNames...)

	for _, k := range sortedKeys(group.AWS.Labels) {
		parts = append(parts, k+"="+group.AWS.Labels[k])
	}

	return newGroupPeer("aws: " + strings.Join(parts, ","))
}

func authType(auth *api.Authentication) flowpb.AuthType {
	if auth == nil {
		return flowpb.AuthType_DISABLED
	}

	switch auth.Mode {
	case api.AuthenticationModeRequired:
		return flowpb.AuthType_SPIRE
	case api.AuthenticationModeAlwaysFail:
		return flowpb.AuthType_TEST_ALWAYS_FAIL
	default:
		return flowpb.AuthType_DISABLED
	}
}

func portsFromRules(rules api.PortRules, icmps api.ICMPRules) []portProto {
	ports := []portProto{}

	for i := range rules {
		for _, pp := range rules[i].Ports {
			ports = append(ports, portProtoFrom(pp))
		}
	}

	return append(ports, icmpPorts(icmps)...)
}

func portsFromDenyRules(rules api.PortDenyRules, icmps api.ICMPRules) []portProto {
	ports := []portProto{}

	for i := range rules {
		for _, pp := range rules[i].Ports {
			ports = append(ports, portProtoFrom(pp))
		}
	}

	return append(ports, icmpPorts(icmps)...)
}

// portProtoFrom keeps the first port of a range and shows named ports as
// port 0, which the frontend renders as "any". Both are known limitations.
func portProtoFrom(pp api.PortProtocol) portProto {
	port, err := strconv.ParseUint(pp.Port, 10, 32)
	if err != nil {
		port = 0
	}

	//nolint:gosec // ParseUint with bitSize 32 bounds the value
	return portProto{port: uint32(port), proto: l4ProtoToIPProtocol(pp.Protocol)}
}

func l4ProtoToIPProtocol(proto api.L4Proto) pbUi.IPProtocol {
	switch proto {
	case api.ProtoTCP:
		return pbUi.IPProtocol_TCP
	case api.ProtoUDP:
		return pbUi.IPProtocol_UDP
	default:
		return pbUi.IPProtocol_UNKNOWN_IP_PROTOCOL
	}
}

func icmpPorts(icmps api.ICMPRules) []portProto {
	ports := []portProto{}

	for i := range icmps {
		for _, field := range icmps[i].Fields {
			proto := pbUi.IPProtocol_ICMP_V4
			if strings.EqualFold(field.Family, "ipv6") {
				proto = pbUi.IPProtocol_ICMP_V6
			}

			ports = append(ports, portProto{port: 0, proto: proto})
		}
	}

	return ports
}

// selectorToLabels turns a label selector into Hubble-style labels and pulls
// the namespace out of it. Match expressions are rendered as readable strings:
// the frontend only shows them, it never evaluates them.
func selectorToLabels(ls *slim_metav1.LabelSelector) ([]string, string) {
	if ls == nil {
		return []string{}, ""
	}

	labels := []string{}
	namespace := ""

	for _, k := range sortedKeys(ls.MatchLabels) {
		key := decodeSelectorKey(k)
		if key == clusterLabelKey {
			continue
		}

		value := string(ls.MatchLabels[k])
		if key == namespaceLabelKey {
			namespace = value
		}

		labels = append(labels, key+"="+value)
	}

	for _, req := range ls.MatchExpressions {
		key := decodeSelectorKey(req.Key)
		if key == clusterLabelKey {
			continue
		}

		switch req.Operator {
		case slim_metav1.LabelSelectorOpIn:
			if key == namespaceLabelKey && len(req.Values) == 1 {
				namespace = req.Values[0]
			}

			if len(req.Values) == 1 {
				labels = append(labels, key+"="+req.Values[0])
			} else {
				labels = append(labels, key+" in ("+strings.Join(req.Values, ",")+")")
			}
		case slim_metav1.LabelSelectorOpNotIn:
			labels = append(labels, key+" notin ("+strings.Join(req.Values, ",")+")")
		case slim_metav1.LabelSelectorOpExists:
			// "namespace exists" is how Cilium says "pods in any namespace"
			if key == namespaceLabelKey {
				continue
			}

			labels = append(labels, key)
		case slim_metav1.LabelSelectorOpDoesNotExist:
			labels = append(labels, "!"+key)
		}
	}

	sort.Strings(labels)

	return labels, namespace
}

// decodeSelectorKey normalizes selector keys to the "source:key" form used by
// Hubble labels. Keys without a source are Kubernetes labels.
func decodeSelectorKey(key string) string {
	if src, rest, ok := strings.Cut(key, ":"); ok && knownLabelSources[src] {
		return normalizeSource(src) + ":" + rest
	}

	if src, rest, ok := strings.Cut(key, "."); ok && knownLabelSources[src] {
		return normalizeSource(src) + ":" + rest
	}

	return "k8s:" + key
}

func normalizeSource(src string) string {
	if src == "any" || src == "unspec" {
		return "k8s"
	}

	return src
}

func compactSelector(labels []string) string {
	parts := []string{}
	for _, lbl := range labels {
		if strings.HasPrefix(lbl, namespaceLabelKey+"=") {
			continue
		}

		parts = append(parts, strings.TrimPrefix(lbl, "k8s:"))
	}

	if len(parts) == 0 {
		return "any"
	}

	return strings.Join(parts, ",")
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	return keys
}
