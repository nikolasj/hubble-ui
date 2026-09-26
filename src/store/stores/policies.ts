import { makeAutoObservable } from 'mobx';

import { PolicyObject, policyKey } from '~/domain/policies';

// PolicyStore keeps the policies of the namespace shown in the policy view
// and which one of them the user is looking at.
export class PolicyStore {
  public namespace: string | null = null;
  public policies: PolicyObject[] = [];
  public warnings: string[] = [];
  public selectedKey: string | null = null;
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

  public setPolicies(namespace: string, policies: PolicyObject[], warnings: string[]) {
    this.namespace = namespace;
    this.policies = policies;
    this.warnings = warnings;
    this.isLoading = false;
    this.error = null;

    if (this.selectedKey != null && !this.byKey.has(this.selectedKey)) {
      this.selectedKey = null;
    }
  }

  public setError(namespace: string, error: string) {
    this.namespace = namespace;
    this.isLoading = false;
    this.error = error;
  }

  public select(key: string | null) {
    this.selectedKey = key;
  }

  public flush() {
    this.namespace = null;
    this.policies = [];
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

  public get selected(): PolicyObject | null {
    if (this.selectedKey == null) return null;

    return this.byKey.get(this.selectedKey) ?? null;
  }

  public policiesForService(serviceId: string): PolicyObject[] {
    return this.policies.filter(p => p.serviceIds.includes(serviceId));
  }

  public isServiceSelected(serviceId: string): boolean {
    return this.selected?.serviceIds.includes(serviceId) ?? false;
  }
}
