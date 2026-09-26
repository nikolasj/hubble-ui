import * as mobx from 'mobx';

import { Store } from '~/store';
import { DataLayer } from '~/data-layer';
import * as storage from '~/storage/local';

import { ServiceCard } from '~/domain/service-map';
import { Application } from '~/domain/common';
import { policyKey } from '~/domain/policies';

import { RefsCollector } from '~/ui/service-map/collector';
import { Options } from '~/ui-layer/common';
import { StatusCenter } from '~/ui-layer/status-center';
import {
  ServiceMapPlacementStrategy,
  ServiceMapArrowStrategy,
} from '~/ui-layer/service-map/coordinates';

// PolicyMap lays out the policy frame with the very same placement and arrow
// strategies the service map uses, they only need a frame to work on.
export class PolicyMap {
  private readonly store: Store;
  private readonly dataLayer: DataLayer;
  private readonly statusCenter: StatusCenter;

  public readonly collector: RefsCollector;
  public readonly placement: ServiceMapPlacementStrategy;
  public readonly arrows: ServiceMapArrowStrategy;

  constructor(opts: Options) {
    this.store = opts.store;
    this.dataLayer = opts.dataLayer;
    this.statusCenter = opts.statusCenter;

    this.collector = new RefsCollector(this.store.policyFrame);
    this.placement = new ServiceMapPlacementStrategy(this.store.policyFrame);
    this.arrows = new ServiceMapArrowStrategy(this.store.policyFrame, this.placement);

    const visibleKinds = storage.getPolicyVisibleKinds();
    if (visibleKinds != null) {
      this.store.policies.setVisibleKinds(visibleKinds);
    }

    this.setupEventHandlers();
  }

  public toggleKind(kind: string) {
    this.store.policies.toggleKind(kind);
    storage.savePolicyVisibleKinds(this.store.policies.visibleKinds);

    this.dataLayer.policyMap.applyVisibility();
  }

  // NOTE: Clicking a card selects the policy that produced it. Repeated clicks
  // walk through all such policies and finally clear the selection.
  public onCardSelect(card: ServiceCard) {
    const keys = this.store.policies.policiesForService(card.id).map(policyKey);
    if (keys.length === 0) {
      this.store.policies.select(null);
      return;
    }

    const idx = keys.indexOf(this.store.policies.selectedKey ?? '');
    const next = idx < 0 ? keys[0] : idx + 1 < keys.length ? keys[idx + 1] : null;

    this.store.policies.select(next);
  }

  public selectPolicy(key: string | null) {
    this.store.policies.select(key);
  }

  public isCardActive(card: ServiceCard): boolean {
    return this.store.policies.isServiceSelected(card.id);
  }

  public cardsMutationsObserved() {
    this.collector.cardsMutationsObserved();
  }

  public clearCoordinates() {
    this.collector.clear();
    this.placement.reset();
    this.arrows.reset();
  }

  public async appToggled(prev: Application, next: Application) {
    if (next === Application.PolicyMap) {
      // NOTE: This drop is needed to fix incorrect cards sizing after app switch
      mobx.runInAction(() => {
        this.clearCoordinates();
      });

      await this.dataLayer.policyMap.appOpened();
      return;
    }

    if (prev === Application.PolicyMap) {
      await this.dataLayer.policyMap.appClosed();
    }
  }

  private setupEventHandlers() {
    this.collector.onCoordsUpdated(coords => {
      mobx.runInAction(() => {
        this.placement.setCardHeights(coords.cards, 0.5);

        coords.accessPoints.forEach(apCoords => {
          const isCardPositioned = !!this.placement.cardsCoords.get(apCoords.cardId);
          if (!isCardPositioned) return;

          this.placement.setAccessPointCoords(apCoords.id, apCoords.bbox.center, 0.5);
        });

        coords.httpEndpoints.forEach(apCoords => {
          const isCardPositioned = !!this.placement.cardsCoords.get(apCoords.cardId);
          if (!isCardPositioned) return;

          this.placement.setHttpEndpointCoords(
            apCoords.cardId,
            apCoords.urlPath,
            apCoords.method,
            apCoords.bbox.center,
          );
        });

        this.arrows.rebuild();
      });
    });

    this.store.policyFrame.onFlushed(() => {
      this.clearCoordinates();
    });

    this.dataLayer.policyMap.onErrors(errs => {
      this.statusCenter.pushPoliciesFetchErrors(errs);
    });
  }
}
