import React, { useEffect } from 'react';
import { observer } from 'mobx-react';
import classnames from 'classnames';
import { Button } from '@blueprintjs/core';
import { animated } from '@react-spring/web';
import { useDrag } from '@use-gesture/react';

import { PolicyObject, policyKey, shortPolicyKind } from '~/domain/policies';

import { usePanelResize } from '~/components/DetailsPanel/hooks/usePanelResize';
import type { ResizeProps } from '~/components/DetailsPanel/hooks/usePanelResize';

import css from './PolicyPanel.scss';

export interface Props {
  namespace: string | null;
  policies: PolicyObject[];
  selected: PolicyObject | null;
  warnings: string[];
  error: string | null;
  isLoading: boolean;
  onSelect?: (key: string | null) => void;
  onRefresh?: () => void;
  onPanelResize?: (resizeProps: ResizeProps) => void;
}

// PolicyPanel lists the policies of the namespace and shows the YAML of the
// selected one. It sits where the flows table is in the service map.
export const PolicyPanel = observer(function PolicyPanel(props: Props) {
  const panelResize = usePanelResize();

  useEffect(() => {
    props.onPanelResize?.(panelResize.props);
  }, [props.onPanelResize, panelResize.props]);

  const bind = useDrag(e => {
    const dy = (e as any).delta[1];
    panelResize.onResize(dy);
  });

  const selectedKey = props.selected ? policyKey(props.selected) : null;
  const showEmptyHint = !props.isLoading && props.error == null && props.policies.length === 0;

  return (
    <div className={css.panel} ref={panelResize.ref} style={panelResize.style}>
      <animated.div {...bind()} className={css.handle}>
        <div className={css.title}>
          Network policies{props.namespace ? ` in ${props.namespace}` : ''}: {props.policies.length}
        </div>

        <Button
          small
          minimal
          icon="refresh"
          text="Refresh"
          loading={props.isLoading}
          onClick={props.onRefresh}
        />
      </animated.div>

      <div className={css.content}>
        <div className={css.list}>
          {props.error != null && <div className={css.error}>{props.error}</div>}

          {props.warnings.map(warning => (
            <div key={warning} className={css.warning}>
              {warning}
            </div>
          ))}

          {showEmptyHint && (
            <div className={css.hint}>No network policies apply to this namespace</div>
          )}

          {props.policies.map(policy => {
            const key = policyKey(policy);
            const isSelected = key === selectedKey;
            const kind = shortPolicyKind(policy.kind);

            return (
              <div
                key={key}
                className={classnames(css.item, { [css.selected]: isSelected })}
                onClick={() => props.onSelect?.(isSelected ? null : key)}
              >
                <span className={classnames(css.kind, css[kind.toLowerCase()])}>{kind}</span>
                <span className={css.name} title={key}>
                  {policy.name}
                </span>
                {!policy.namespace && <span className={css.scope}>cluster-wide</span>}
                {policy.parseError && (
                  <span className={css.parseError} title={policy.parseError}>
                    parse error
                  </span>
                )}
              </div>
            );
          })}
        </div>

        <div className={css.yaml}>
          {props.selected ? (
            <>
              {props.selected.description && (
                <div className={css.description}>{props.selected.description}</div>
              )}
              <pre className={css.code}>{props.selected.yaml}</pre>
            </>
          ) : (
            <div className={css.hint}>
              Select a policy to see its YAML. Clicking a card selects the policies that produced
              it.
            </div>
          )}
        </div>
      </div>
    </div>
  );
});
