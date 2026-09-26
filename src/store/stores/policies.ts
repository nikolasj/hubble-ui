import { makeAutoObservable } from 'mobx';

import { HubbleService, HubbleLink } from '~/domain/hubble';
import { PolicyObject, PolicyKind, policyKey } from '~/domain/policies';

// Cluster-wide policies apply to every namespace and tend to bury the
// namespace's own rules, so they are hidden until asked for.
export const DEFAULT_VISIBLE_POLICY_KINDS: string[] = [
  PolicyKind.CiliumNetworkPolicy,
  PolicyKind.NetworkPolicy,
];

// PolicyStore keeps the policies of the namespace shown in the policy view,
// the cards and links the backend built from them, which policy kinds the
// user wants to see and which policy is selected.
export class PolicyStore {
  public namespace: string | null = null;
  public policies: PolicyObject[] = [];
  public services: HubbleService[] = [];
  public links: HubbleLink[] = [];
  public warnings: string[] = [];
  public selectedKey: string | null = null;
  public visibleKinds: Set<string> = new Set(DEFAULT_VISIBLE_POLICY_KINDS);
  public isLoading = false;
  public error: string | null = null;

  constructor() {
    makeAutoObservable(this, void 0, {
      autoBind: true,
    });
  }

  public setLoading(namespace: string) {
    this.namespace = namespace;
    this.isLoading = true;
    this.error = null;
  }

  public setPolicies(
    namespace: string,
    policies: PolicyObject[],
    warnings: string[],
    services: HubbleService[],
    links: HubbleLink[],
  ) {
    this.namespace = namespace;
    this.policies = policies;
    this.warnings = warnings;
    this.services = services;
    this.links = links;
    this.isLoading = false;
    this.error = null;

    this.dropStaleSelection();
  }

  public setError(namespace: string, error: string) {
    this.namespace = namespace;
    this.isLoading = false;
    this.error = error;
  }

  public select(key: string | null) {
    this.selectedKey = key;
  }

  public setVisibleKinds(kinds: Set<string>) {
    this.visibleKinds = new Set(kinds);
    this.dropStaleSelection();
  }

  public toggleKind(kind: string) {
    const next = new Set(this.visibleKinds);
    if (next.has(kind)) {
      next.delete(kind);
    } else {
      next.add(kind);
    }

    this.setVisibleKinds(next);
  }

  public isKindVisible(kind: string): boolean {
    return this.visibleKinds.has(kind);
  }

  public flush() {
    this.namespace = null;
    this.policies = [];
    this.services = [];
    this.links = [];
    this.warnings = [];
    this.selectedKey = null;
    this.isLoading = false;
    this.error = null;
  }

  public get byKey(): Map<string, PolicyObject> {
    const map = new Map<string, PolicyObject>();
    this.policies.forEach(p => map.set(policyKey(p), p));

    return map;
  }

  public get visiblePolicies(): PolicyObject[] {
    return this.policies.filter(p => this.visibleKinds.has(p.kind));
  }

  public get countsByKind(): Map<string, number> {
    const counts = new Map<string, number>();
    this.policies.forEach(p => counts.set(p.kind, (counts.get(p.kind) ?? 0) + 1));

    return counts;
  }

  public get visibleServiceIds(): Set<string> {
    const ids = new Set<string>();
    this.visiblePolicies.forEach(p => p.serviceIds.forEach(id => ids.add(id)));

    return ids;
  }

  public get visibleLinkIds(): Set<string> {
    const ids = new Set<string>();
    this.visiblePolicies.forEach(p => p.linkIds.forEach(id => ids.add(id)));

    return ids;
  }

  // NOTE: Cards are shared between policies, so a card stays on the map as
  // long as at least one visible policy produced it.
  public get visibleServices(): HubbleService[] {
    const ids = this.visibleServiceIds;

    return this.services.filter(svc => ids.has(svc.id));
  }

  public get visibleLinks(): HubbleLink[] {
    const linkIds = this.visibleLinkIds;
    const serviceIds = this.visibleServiceIds;

    return this.links.filter(
      link =>
        linkIds.has(link.id) && serviceIds.has(link.sourceId) && serviceIds.has(link.destinationId),
    );
  }

  public get selected(): PolicyObject | null {
    if (this.selectedKey == null) return null;

    return this.byKey.get(this.selectedKey) ?? null;
  }

  public policiesForService(serviceId: string): PolicyObject[] {
    return this.visiblePolicies.filter(p => p.serviceIds.includes(serviceId));
  }

  public isServiceSelected(serviceId: string): boolean {
    return this.selected?.serviceIds.includes(serviceId) ?? false;
  }

  private dropStaleSelection() {
    const selected = this.selected;
    if (selected == null) return;

    if (!this.visibleKinds.has(selected.kind)) {
      this.selectedKey = null;
    }
  }
}
