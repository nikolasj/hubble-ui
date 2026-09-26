package policy

import (
	"fmt"
	"sort"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"google.golang.org/protobuf/types/known/timestamppb"

	pbUi "github.com/cilium/hubble-ui/backend/proto/ui"
)

// Graph is the static access map of one namespace: the same cards and links
// the live service map uses, but derived from policies instead of flows.
type Graph struct {
	Services []*pbUi.Service
	Links    []*pbUi.ServiceLink

	// Ids of services and links each policy (by Object.Key()) contributed
	ServiceIDs map[string][]string
	LinkIDs    map[string][]string
}

type graphBuilder struct {
	namespace  string
	services   map[string]*pbUi.Service
	links      map[string]*pbUi.ServiceLink
	identities map[uint32]bool
	serviceIDs map[string]map[string]bool
	linkIDs    map[string]map[string]bool
}

// BuildGraph draws every subject of the given policies that lives in the
// namespace. Cluster-wide subjects without a namespace of their own are drawn
// as if they lived there, because that is what the user is looking at.
func BuildGraph(namespace string, objects []*Object) *Graph {
	b := &graphBuilder{
		namespace:  namespace,
		services:   map[string]*pbUi.Service{},
		links:      map[string]*pbUi.ServiceLink{},
		identities: map[uint32]bool{},
		serviceIDs: map[string]map[string]bool{},
		linkIDs:    map[string]map[string]bool{},
	}

	for _, obj := range objects {
		if obj == nil {
			continue
		}

		for _, s := range obj.subjects {
			if s.self.namespace != "" && s.self.namespace != namespace {
				continue
			}

			b.addSubject(obj.Key(), s)
		}
	}

	return b.result()
}

func (b *graphBuilder) addSubject(policyKey string, s *subject) {
	self := s.self
	if self.namespace == "" {
		self = newPodsPeer(
			append(sortedCopy(self.labels), namespaceLabelKey+"="+b.namespace),
			b.namespace,
		)
	}

	subjectID := b.ensureService(policyKey, self)
	svc := b.services[subjectID]
	svc.IngressPolicyEnforced = svc.GetIngressPolicyEnforced() || s.ingressDefaultDeny
	svc.EgressPolicyEnforced = svc.GetEgressPolicyEnforced() || s.egressDefaultDeny

	for _, e := range s.edges {
		peerID := b.ensureService(policyKey, e.peer)

		sourceID, destinationID := peerID, subjectID
		if !e.ingress {
			sourceID, destinationID = subjectID, peerID
		}

		for _, pp := range e.ports {
			b.ensureLink(policyKey, sourceID, destinationID, pp, e.deny, e.auth)
		}
	}
}

func (b *graphBuilder) ensureService(policyKey string, p *peer) string {
	id := "policy:" + p.key()

	if _, exists := b.services[id]; !exists {
		b.services[id] = &pbUi.Service{
			Id:                id,
			Name:              p.caption(),
			Namespace:         p.namespace,
			Labels:            sortedCopy(p.labels),
			DnsNames:          append([]string{}, p.dnsNames...),
			Workloads:         p.workloads,
			Identity:          b.uniqueIdentity(id),
			CreationTimestamp: timestamppb.Now(),
		}
	}

	b.remember(b.serviceIDs, policyKey, id)

	return id
}

func (b *graphBuilder) ensureLink(
	policyKey, sourceID, destinationID string,
	pp portProto,
	deny bool,
	auth flowpb.AuthType,
) {
	protoName := pbUi.IPProtocol_name[int32(pp.proto)]
	id := fmt.Sprintf("%s %s %s:%d", sourceID, protoName, destinationID, pp.port)

	verdict := flowpb.Verdict_FORWARDED
	if deny {
		verdict = flowpb.Verdict_DROPPED
		id += " deny"
	}

	if _, exists := b.links[id]; !exists {
		b.links[id] = &pbUi.ServiceLink{
			Id:              id,
			SourceId:        sourceID,
			DestinationId:   destinationID,
			DestinationPort: pp.port,
			IpProtocol:      pp.proto,
			Verdict:         verdict,
			AuthType:        auth,
			IsEncrypted:     false,
		}
	}

	b.remember(b.linkIDs, policyKey, id)
}

func (b *graphBuilder) uniqueIdentity(id string) uint32 {
	identity := stableIdentity(id)
	for b.identities[identity] {
		identity++
	}

	b.identities[identity] = true

	return identity
}

func (b *graphBuilder) remember(index map[string]map[string]bool, policyKey, id string) {
	if index[policyKey] == nil {
		index[policyKey] = map[string]bool{}
	}

	index[policyKey][id] = true
}

func (b *graphBuilder) result() *Graph {
	g := &Graph{
		Services:   make([]*pbUi.Service, 0, len(b.services)),
		Links:      make([]*pbUi.ServiceLink, 0, len(b.links)),
		ServiceIDs: map[string][]string{},
		LinkIDs:    map[string][]string{},
	}

	for _, id := range sortedKeys(b.services) {
		g.Services = append(g.Services, b.services[id])
	}

	for _, id := range sortedKeys(b.links) {
		g.Links = append(g.Links, b.links[id])
	}

	for policyKey, ids := range b.serviceIDs {
		g.ServiceIDs[policyKey] = sortedKeys(ids)
	}

	for policyKey, ids := range b.linkIDs {
		g.LinkIDs[policyKey] = sortedKeys(ids)
	}

	return g
}

// Sorted returns the objects ordered by kind, namespace and name so that the
// list shown to the user is stable between requests.
func Sorted(objects []*Object) []*Object {
	res := make([]*Object, 0, len(objects))
	for _, obj := range objects {
		if obj != nil {
			res = append(res, obj)
		}
	}

	sort.Slice(res, func(i, j int) bool {
		return res[i].Key() < res[j].Key()
	})

	return res
}
