package policy

import (
	"sort"
	"strings"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	pbUi "github.com/cilium/hubble-ui/backend/proto/ui"
)

const (
	namespaceNameLabel = "kubernetes.io/metadata.name"

	// namespaceMetaKeyPrefix is namespaceMetaLabelPrefix without the label
	// source, i.e. what goes after "k8s:".
	namespaceMetaKeyPrefix = "io.cilium.k8s.namespace.labels."
)

// subjectsFromNetworkPolicy draws a Kubernetes NetworkPolicy the way Cilium
// enforces it: an empty peer list matches everything and an empty port list
// matches all ports of a rule.
func subjectsFromNetworkPolicy(np *networkingv1.NetworkPolicy) []*subject {
	namespace := np.Namespace

	labels := k8sSelectorToLabels(&np.Spec.PodSelector, "")
	labels = append(labels, namespaceLabelKey+"="+namespace)

	s := &subject{self: newPodsPeer(labels, namespace)}
	s.ingressDefaultDeny, s.egressDefaultDeny = policyTypes(np)

	if s.ingressDefaultDeny {
		for i := range np.Spec.Ingress {
			rule := &np.Spec.Ingress[i]
			peers := networkPolicyPeers(rule.From, namespace)
			ports := networkPolicyPorts(rule.Ports)

			s.addEdges(peers, ports, true, true, false, flowpb.AuthType_DISABLED)
		}
	}

	if s.egressDefaultDeny {
		for i := range np.Spec.Egress {
			rule := &np.Spec.Egress[i]
			peers := networkPolicyPeers(rule.To, namespace)
			ports := networkPolicyPorts(rule.Ports)

			s.addEdges(peers, ports, true, false, false, flowpb.AuthType_DISABLED)
		}
	}

	return []*subject{s}
}

// policyTypes returns whether ingress and egress are governed by the policy.
// Without explicit policyTypes, ingress always is and egress only when the
// policy has egress rules.
func policyTypes(np *networkingv1.NetworkPolicy) (bool, bool) {
	if len(np.Spec.PolicyTypes) == 0 {
		return true, len(np.Spec.Egress) > 0
	}

	ingress, egress := false, false
	for _, t := range np.Spec.PolicyTypes {
		switch t {
		case networkingv1.PolicyTypeIngress:
			ingress = true
		case networkingv1.PolicyTypeEgress:
			egress = true
		}
	}

	return ingress, egress
}

func networkPolicyPeers(peers []networkingv1.NetworkPolicyPeer, namespace string) []*peer {
	res := []*peer{}

	for i := range peers {
		p := &peers[i]

		switch {
		case p.IPBlock != nil:
			res = append(res, newCIDRPeer(p.IPBlock.CIDR))
		case p.NamespaceSelector != nil:
			res = append(res, namespaceSelectorPeer(p.NamespaceSelector, p.PodSelector))
		case p.PodSelector != nil:
			labels := k8sSelectorToLabels(p.PodSelector, "")
			labels = append(labels, namespaceLabelKey+"="+namespace)

			res = append(res, newPodsPeer(labels, namespace))
		}
	}

	return res
}

// namespaceSelectorPeer describes pods in other namespaces. A selector on the
// namespace name pins the peer to that namespace, anything else is shown as
// namespace labels the way Cilium encodes them.
func namespaceSelectorPeer(nsSelector, podSelector *metav1.LabelSelector) *peer {
	namespace := ""
	labels := []string{}

	if name, ok := nsSelector.MatchLabels[namespaceNameLabel]; ok {
		namespace = name
		labels = append(labels, namespaceLabelKey+"="+name)
	}

	for _, lbl := range k8sSelectorToLabels(nsSelector, namespaceMetaKeyPrefix) {
		if strings.HasPrefix(lbl, namespaceMetaLabelPrefix+namespaceNameLabel+"=") {
			continue
		}

		labels = append(labels, lbl)
	}

	if podSelector != nil {
		labels = append(labels, k8sSelectorToLabels(podSelector, "")...)
	}

	return newPodsPeer(labels, namespace)
}

func networkPolicyPorts(ports []networkingv1.NetworkPolicyPort) []portProto {
	res := []portProto{}

	for i := range ports {
		p := &ports[i]

		proto := pbUi.IPProtocol_TCP
		if p.Protocol != nil {
			switch *p.Protocol {
			case corev1.ProtocolUDP:
				proto = pbUi.IPProtocol_UDP
			case corev1.ProtocolSCTP:
				proto = pbUi.IPProtocol_UNKNOWN_IP_PROTOCOL
			case corev1.ProtocolTCP:
				proto = pbUi.IPProtocol_TCP
			}
		}

		port := uint32(0)
		if p.Port != nil && p.Port.Type == intstr.Int && p.Port.IntVal > 0 {
			//nolint:gosec // guarded by the positive check above
			port = uint32(p.Port.IntVal)
		}

		res = append(res, portProto{port: port, proto: proto})
	}

	return res
}

// k8sSelectorToLabels renders a Kubernetes label selector as Hubble labels.
// keyPrefix is inserted after the "k8s:" source, which is how Cilium encodes
// namespace labels ("k8s:io.cilium.k8s.namespace.labels.<key>").
func k8sSelectorToLabels(ls *metav1.LabelSelector, keyPrefix string) []string {
	if ls == nil {
		return []string{}
	}

	labels := []string{}

	for _, k := range sortedKeys(ls.MatchLabels) {
		labels = append(labels, "k8s:"+keyPrefix+k+"="+ls.MatchLabels[k])
	}

	for _, req := range ls.MatchExpressions {
		key := "k8s:" + keyPrefix + req.Key

		switch req.Operator {
		case metav1.LabelSelectorOpIn:
			if len(req.Values) == 1 {
				labels = append(labels, key+"="+req.Values[0])
			} else {
				labels = append(labels, key+" in ("+strings.Join(req.Values, ",")+")")
			}
		case metav1.LabelSelectorOpNotIn:
			labels = append(labels, key+" notin ("+strings.Join(req.Values, ",")+")")
		case metav1.LabelSelectorOpExists:
			labels = append(labels, key)
		case metav1.LabelSelectorOpDoesNotExist:
			labels = append(labels, "!"+key)
		}
	}

	sort.Strings(labels)

	return labels
}
