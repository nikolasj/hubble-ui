import { BackendAPI, PoliciesRequest } from '~/api/customprotocol';
import { CustomError } from '~/api/customprotocol-core';

import * as uipb from '~backend/proto/ui/ui_pb';

import * as helpers from '~/domain/helpers';
import { FiltersDiff } from '~/domain/filtering';
import { policyObjectFromPb } from '~/domain/policies';
import { ServiceMap } from '~/domain/service-map';

import { Store } from '~/store';
import { EventEmitter } from '~/utils/emitter';

import { Options } from './common';

export enum Event {
  Errors = 'errors',
}

export type Handlers = {
  [Event.Errors]: (errs: CustomError[]) => void;
};

// PolicyMap loads the static access graph of the current namespace: the
// policies that apply to it and the cards and links the backend built from
// them. Unlike the service map there is nothing to stream, one request is
// enough until the namespace changes or the user asks for a refresh.
export class PolicyMap extends EventEmitter<Handlers> {
  private backendAPI: BackendAPI;
  private store: Store;

  private request: PoliciesRequest | null = null;
  private isAppActive = false;

  constructor(opts: Options) {
    super(true);

    this.store = opts.store;
    this.backendAPI = opts.backendAPI;
  }

  public onErrors(fn: Handlers[Event.Errors]): this {
    this.on(Event.Errors, fn);
    return this;
  }

  public async appOpened() {
    this.isAppActive = true;
    await this.fetch();
  }

  public async appClosed() {
    this.isAppActive = false;
    await this.dropFetch();
  }

  public async filtersChanged(f: FiltersDiff) {
    if (!this.isAppActive || !f.namespace.changed) return;

    await this.fetch();
  }

  public async refetch() {
    if (!this.isAppActive) return;

    await this.fetch(true);
  }

  public async fetch(force = false) {
    const namespace = this.store.namespaces.currentRaw;

    if (namespace == null) {
      await this.dropFetch();
      this.store.policies.flush();
      this.store.policyFrame.flush();
      return;
    }

    // NOTE: The same namespace is requested from several places on a route
    // change, one request is enough.
    const policies = this.store.policies;
    const isSameNamespace = policies.namespace === namespace && policies.error == null;
    if (!force && isSameNamespace && (this.request != null || !policies.isLoading)) return;

    await this.dropFetch();
    policies.setLoading(namespace);

    this.request = this.backendAPI
      .policies(namespace)
      .onResponse(resp => this.handleResponse(namespace, resp))
      .onErrors(errs => this.handleErrors(namespace, errs))
      .run();
  }

  public async dropFetch() {
    if (this.request == null) return;

    const request = this.request;
    this.request = null;

    request.offAllEvents();
    await request.stop();
  }

  private handleResponse(namespace: string, resp: uipb.GetPoliciesResponse) {
    // NOTE: The user could have switched namespace while the request was in flight
    if (this.store.namespaces.currentRaw !== namespace) return;

    const services = resp.services.map(helpers.relayServiceFromPb);
    const links = resp.links.map(helpers.relayServiceLinkFromPb);
    const policies = resp.policies.map(policyObjectFromPb);

    this.store.policyFrame.replaceServiceMap(ServiceMap.fromHubbleParts(services, links));
    this.store.policies.setPolicies(namespace, policies, resp.warnings.slice());
  }

  private handleErrors(namespace: string, errs: CustomError[]) {
    const message = errs.map(err => err.message).join('; ');

    this.store.policies.setError(namespace, message);
    this.emit(Event.Errors, errs);
  }
}
