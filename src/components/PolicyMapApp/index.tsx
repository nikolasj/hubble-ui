import React, { useCallback, useEffect, useState } from 'react';
import { observer } from 'mobx-react';
import * as mobx from 'mobx';

import { TopBar } from '~/components/TopBar';
import { Map } from '~/components/Map';
import { LoadingOverlay } from '~/components/Misc/LoadingOverlay';
import { ServiceMapCard } from '~/components/ServiceMapCard';
import { CardProps } from '~/components/Card';
import { ServiceMapArrowsRenderer } from '~/components/ServiceMapArrowRenderer';
import { WelcomeScreen } from '~/components/ServiceMapApp/WelcomeScreen';
import type { ResizeProps } from '~/components/DetailsPanel/hooks/usePanelResize';

import { Application } from '~/domain/common';
import { ServiceCard } from '~/domain/service-map';

import { useApplication } from '~/application';
import { sizes } from '~/ui/vars';

import { PolicyPanel } from './PolicyPanel';
import css from './styles.scss';

// PolicyMapApp shows what the network policies of a namespace allow and deny,
// drawn with the service map renderer, and the YAML of those policies.
export const PolicyMapApp = observer(function PolicyMapApp() {
  const { store, ui, dataLayer } = useApplication();

  const [mapVisibleHeight, setMapVisibleHeight] = useState<number | null>(null);
  const [mapWasDragged, setMapWasDragged] = useState(false);

  useEffect(() => {
    setMapWasDragged(false);
  }, [store.namespaces.currentRaw]);

  const onCardSelect = useCallback((card: ServiceCard) => {
    ui.policyMap.onCardSelect(card);
  }, []);

  const onPolicySelect = useCallback((key: string | null) => {
    ui.policyMap.selectPolicy(key);
  }, []);

  const onRefresh = useCallback(() => {
    dataLayer.policyMap.refetch();
  }, []);

  const onToggleKind = useCallback((kind: string) => {
    ui.policyMap.toggleKind(kind);
  }, []);

  const onPanelResize = useCallback((resizeProps: ResizeProps) => {
    const vh = resizeProps.panelTopInPixels - sizes.topBarHeight;
    setMapVisibleHeight(vh);
  }, []);

  const onMapDrag = useCallback((val: boolean) => {
    setMapWasDragged(val);
  }, []);

  const cardRenderer = mobx.action((props: CardProps<ServiceCard>) => {
    const l7endpoints = store.policyFrame.interactions.l7endpoints;

    return (
      <ServiceMapCard
        {...props}
        key={props.card.id}
        active={ui.policyMap.isCardActive(props.card)}
        isUnsizedMode={props.isUnsizedMode}
        collector={ui.policyMap.collector}
        currentNamespace={store.namespaces.currentRaw}
        className={props.className}
        l7endpoints={l7endpoints.forReceiver(props.card.id)}
        maxHttpEndpointsVisible={5}
        isClusterMeshed={false}
        onHeaderClick={onCardSelect}
      />
    );
  });

  const RenderedTopBar = (
    <TopBar
      transferState={dataLayer.transferState}
      status={dataLayer.transferState.deploymentStatus || undefined}
      namespaces={store.availableNamespaces}
      currentNamespace={store.currentNamespace}
      onNamespaceChange={ns => ui.controls.namespaceChanged(ns?.namespace)}
      selectedVerdict={store.controls.activeVerdict}
      selectedHttpStatus={store.controls.httpStatus}
      flowFilters={store.controls.filteredFlowFilters}
      showHost={store.controls.showHost}
      showKubeDns={store.controls.showKubeDns}
      showRemoteNode={store.controls.showRemoteNode}
      showPrometheusApp={store.controls.showPrometheusApp}
      onShowPrometheusAppToggle={() => ui.controls.toggleShowPrometheusApp()}
      currentApp={Application.PolicyMap}
      onAppChange={app => ui.controls.applicationChanged(app)}
      hideFlowControls
    />
  );

  if (!store.currentNamespace) {
    return (
      <div className={css.app}>
        {RenderedTopBar}
        <WelcomeScreen
          namespaces={store.availableNamespaces}
          onNamespaceChange={ns => ui.controls.namespaceChanged(ns?.namespace)}
        />
      </div>
    );
  }

  const namespace = store.namespaces.currentRaw;
  const cards = store.policyFrame.services.cardsList;
  const { policies } = store;

  let overlayText = 'Loading network policies…';
  if (!policies.isLoading) {
    if (policies.error != null) {
      overlayText = `Failed to load network policies: ${policies.error}`;
    } else if (policies.policies.length > 0 && policies.visiblePolicies.length === 0) {
      overlayText = 'All policies of this namespace are of hidden kinds, enable them below';
    } else {
      overlayText = `No network policy grants or denies anything in ${namespace} namespace`;
    }
  }

  return (
    <div className={css.app}>
      {RenderedTopBar}

      <div className={css.map}>
        {cards.length > 0 ? (
          <Map
            namespace={namespace}
            namespaceBBox={ui.policyMap.placement.namespaceBBox}
            placement={ui.policyMap.placement}
            arrows={ui.policyMap.arrows}
            arrowsRenderer={ServiceMapArrowsRenderer}
            cards={cards}
            cardRenderer={cardRenderer}
            visibleHeight={mapVisibleHeight ?? 0}
            wasDragged={mapWasDragged}
            onMapDrag={onMapDrag}
            onCardMutated={() => ui.policyMap.cardsMutationsObserved()}
          />
        ) : (
          <LoadingOverlay
            height={mapVisibleHeight ?? '50%'}
            text={overlayText}
            isSpinnerHidden={!policies.isLoading}
          />
        )}
      </div>

      <PolicyPanel
        namespace={namespace}
        policies={policies.visiblePolicies}
        totalCount={policies.policies.length}
        countsByKind={policies.countsByKind}
        visibleKinds={policies.visibleKinds}
        selected={policies.selected}
        warnings={policies.warnings}
        error={policies.error}
        isLoading={policies.isLoading}
        onSelect={onPolicySelect}
        onToggleKind={onToggleKind}
        onRefresh={onRefresh}
        onPanelResize={onPanelResize}
      />
    </div>
  );
});
